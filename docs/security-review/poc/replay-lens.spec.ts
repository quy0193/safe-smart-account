import { expect } from "chai";
import hre, { deployments, ethers } from "hardhat";
import { AddressZero } from "@ethersproject/constants";
import { getSafe, getCompatFallbackHandler, getSignMessageLib, deployContractFromSource } from "../../../test/utils/setup";
import {
    buildSignatureBytes,
    buildContractSignature,
    buildSafeTransaction,
    calculateSafeTransactionHash,
    calculateSafeMessageHash,
    executeContractCallWithSigners,
    executeTx,
    safeSignTypedData,
    signHash,
} from "../../../src/utils/execution";
import { chainId } from "../../../test/utils/encoding";

// Security review PoC for the cross-cutting replay / domain-binding lens.
// Run with: npx hardhat test docs/security-review/poc/replay-lens.spec.ts
describe("Security review PoC: replay / domain binding lens", () => {
    const setupTests = deployments.createFixture(async ({ deployments }) => {
        await deployments.fixture();
        const handler = await getCompatFallbackHandler();
        const handlerAddress = await handler.getAddress();
        const signers = await ethers.getSigners();
        return { handler, handlerAddress, signers, signLib: await getSignMessageLib() };
    });

    const approvedSig = (addr: string) => ({
        signer: addr,
        data: "0x" + "000000000000000000000000" + addr.slice(2) + "00".repeat(32) + "01",
    });

    it("v=1 with r=0 via the handler (executor=0) is rejected by the ordering check (GS026)", async () => {
        const {
            handlerAddress,
            signers: [u1],
        } = await setupTests();
        const safe = await getSafe({ owners: [u1.address], threshold: 1, fallbackHandler: handlerAddress });
        const validator = await getCompatFallbackHandler(await safe.getAddress());
        const dataHash = ethers.keccak256("0xbaddad");
        const zeroApproved = "0x" + "00".repeat(64) + "01";
        await expect(validator.isValidSignature.staticCall(dataHash, zeroApproved)).to.be.revertedWith("GS026");
        // direct checkNSignatures with executor == 0 as well
        await expect(safe["checkNSignatures(address,bytes32,bytes,uint256)"](AddressZero, dataHash, zeroApproved, 1)).to.be.revertedWith(
            "GS026",
        );
    });

    it("approvedHashes survive owner removal and revive on re-add (documented: no revocation)", async () => {
        const {
            handlerAddress,
            signers: [u1, u2],
        } = await setupTests();
        const safe = await getSafe({ owners: [u1.address, u2.address], threshold: 1, fallbackHandler: handlerAddress });
        const safeAddress = await safe.getAddress();
        const validator = await getCompatFallbackHandler(safeAddress);
        const dataHash = ethers.keccak256("0xbaddad");
        const msgHash = calculateSafeMessageHash(safeAddress, dataHash, await chainId());

        await safe.connect(u2).approveHash(msgHash);
        const sig = buildSignatureBytes([approvedSig(u2.address)]);
        expect(await validator.isValidSignature.staticCall(dataHash, sig)).to.eq("0x1626ba7e");

        // remove u2 (prev owner in the linked list is u1 since u1 is the first owner)
        await executeContractCallWithSigners(safe, safe, "removeOwner", [u1.address, u2.address, 1], [u1]);
        expect(await safe.isOwner(u2.address)).to.eq(false);
        await expect(validator.isValidSignature.staticCall(dataHash, sig)).to.be.revertedWith("GS026");
        expect(await safe.approvedHashes(u2.address, msgHash)).to.eq(1n);

        // re-add u2 -> approval is live again
        await executeContractCallWithSigners(safe, safe, "addOwnerWithThreshold", [u2.address, 1], [u1]);
        expect(await validator.isValidSignature.staticCall(dataHash, sig)).to.eq("0x1626ba7e");
    });

    it("mutual Safe ownership: nested contract signatures are bounded by the signature bytes and work", async () => {
        const {
            handlerAddress,
            signers: [u1, u2, receiver],
        } = await setupTests();
        const cid = await chainId();
        const safeA = await getSafe({ owners: [u1.address], threshold: 1, fallbackHandler: handlerAddress });
        const safeB = await getSafe({ owners: [u2.address], threshold: 1, fallbackHandler: handlerAddress });
        const a = await safeA.getAddress();
        const b = await safeB.getAddress();
        await executeContractCallWithSigners(safeA, safeA, "addOwnerWithThreshold", [b, 1], [u1]);
        await executeContractCallWithSigners(safeB, safeB, "addOwnerWithThreshold", [a, 1], [u2]);

        await u1.sendTransaction({ to: a, value: ethers.parseEther("1") });
        const tx = buildSafeTransaction({ to: receiver.address, value: ethers.parseEther("1"), nonce: await safeA.nonce() });
        const tA = calculateSafeTransactionHash(a, tx, cid);
        // B signs T_A  -> needs sig over M_B(T_A)
        const mB1 = calculateSafeMessageHash(b, tA, cid);
        // A (owner of B) signs M_B(T_A) -> needs sig over M_A(M_B(T_A))
        const mA1 = calculateSafeMessageHash(a, mB1, cid);
        // B (owner of A) signs M_A(M_B(T_A)) -> needs sig over M_B(M_A(M_B(T_A)))
        const mB2 = calculateSafeMessageHash(b, mA1, cid);
        const leaf = await signHash(u2, mB2);
        const sigB2 = buildSignatureBytes([buildContractSignature(b, leaf.data)]); // for A.checkSignatures(mA1)
        const sigA1 = buildSignatureBytes([buildContractSignature(a, sigB2)]); // for B.checkSignatures(mB1)
        const outer = [buildContractSignature(b, sigA1)]; // for A.checkSignatures(tA)

        const before = await ethers.provider.getBalance(receiver.address);
        await executeTx(safeA, tx, outer);
        expect((await ethers.provider.getBalance(receiver.address)) - before).to.eq(ethers.parseEther("1"));
    });

    it("a gas-burning / reverting nested validator surfaces as GS024 (no silent success)", async () => {
        const {
            handlerAddress,
            signers: [u1],
        } = await setupTests();
        const burner = await deployContractFromSource(
            u1,
            `contract Burner { function isValidSignature(bytes32, bytes memory) external view returns (bytes4) { while (true) { assembly { pop(sload(0)) } } return 0x1626ba7e; } }`,
        );
        const burnerAddress = await burner.getAddress();
        const safe = await getSafe({ owners: [burnerAddress, u1.address], threshold: 1, fallbackHandler: handlerAddress });
        const safeAddress = await safe.getAddress();
        const tx = buildSafeTransaction({ to: safeAddress, nonce: await safe.nonce() });
        const txHash = calculateSafeTransactionHash(safeAddress, tx, await chainId());
        const sigs = buildSignatureBytes([buildContractSignature(burnerAddress, "0x")]);
        await expect(safe["checkSignatures(address,bytes32,bytes)"](AddressZero, txHash, sigs, { gasLimit: 2_000_000 })).to.be.revertedWith(
            "GS024",
        );
    });

    it("precompile addresses can be added as owners but cannot produce a valid contract signature", async () => {
        const {
            handlerAddress,
            signers: [u1],
        } = await setupTests();
        const identity = "0x0000000000000000000000000000000000000004";
        const sha256 = "0x0000000000000000000000000000000000000002";
        const safe = await getSafe({ owners: [u1.address, identity, sha256], threshold: 1, fallbackHandler: handlerAddress });
        const safeAddress = await safe.getAddress();
        expect(await safe.isOwner(identity)).to.eq(true);
        const tx = buildSafeTransaction({ to: safeAddress, nonce: await safe.nonce() });
        const txHash = calculateSafeTransactionHash(safeAddress, tx, await chainId());
        for (const p of [identity, sha256]) {
            const sigs = buildSignatureBytes([buildContractSignature(p, "0x1626ba7e" + "00".repeat(28))]);
            await expect(safe["checkSignatures(address,bytes32,bytes)"](AddressZero, txHash, sigs)).to.be.revertedWith("GS024");
        }
    });

    it("tx-hash signatures and message-hash signatures are not interchangeable", async () => {
        const {
            handlerAddress,
            signers: [u1, u2],
        } = await setupTests();
        const cid = await chainId();
        const safe = await getSafe({ owners: [u1.address, u2.address], threshold: 2, fallbackHandler: handlerAddress });
        const safeAddress = await safe.getAddress();
        const validator = await getCompatFallbackHandler(safeAddress);
        const tx = buildSafeTransaction({ to: safeAddress, nonce: await safe.nonce() });
        const txHash = calculateSafeTransactionHash(safeAddress, tx, cid);
        // owners sign the SafeMessage wrapping of the tx hash (what a dapp 1271 flow would produce)
        const msgHash = calculateSafeMessageHash(safeAddress, txHash, cid);
        const msgSigs = [await signHash(u1, msgHash), await signHash(u2, msgHash)];
        await expect(executeTx(safe, tx, msgSigs)).to.be.revertedWith("GS026");
        // owners sign the tx hash directly: cannot be used as a 1271 message signature for txHash
        const txSigs = [await safeSignTypedData(u1, safeAddress, tx), await safeSignTypedData(u2, safeAddress, tx)];
        await expect(validator.isValidSignature.staticCall(txHash, buildSignatureBytes(txSigs))).to.be.revertedWith("GS026");
        // but the message signatures validate as a 1271 signature for txHash
        expect(await validator.isValidSignature.staticCall(txHash, buildSignatureBytes(msgSigs))).to.eq("0x1626ba7e");
    });

    it("executor shortcut (v=1, r=msg.sender) requires msg.sender to be an owner", async () => {
        const {
            signers: [u1, u2],
        } = await setupTests();
        const safe = await getSafe({ owners: [u1.address], threshold: 1 });
        const safeAddress = await safe.getAddress();
        const tx = buildSafeTransaction({ to: safeAddress, nonce: await safe.nonce() });
        await expect(executeTx(safe.connect(u2), tx, [approvedSig(u2.address)])).to.be.revertedWith("GS026");
        await expect(executeTx(safe.connect(u2), tx, [approvedSig(u1.address)])).to.be.revertedWith("GS025");
        await executeTx(safe.connect(u1), tx, [approvedSig(u1.address)]);
        expect(await safe.nonce()).to.eq(1n);
    });

    it("SignMessageLib: only abi.encode(hash)-shaped messages are verifiable through isValidSignature(bytes32)", async () => {
        const {
            handlerAddress,
            signLib,
            signers: [u1, u2],
        } = await setupTests();
        const safe = await getSafe({ owners: [u1.address, u2.address], threshold: 2, fallbackHandler: handlerAddress });
        const validator = await getCompatFallbackHandler(await safe.getAddress());
        const raw = "0xbaddad";
        const rawHash = ethers.keccak256(raw);
        await executeContractCallWithSigners(safe, signLib, "signMessage", [raw], [u1, u2], true);
        // The docs say "pass the pre-image of the message hash" but the only ERC-1271 entry point takes a bytes32
        await expect(validator.isValidSignature.staticCall(rawHash, "0x")).to.be.revertedWith("Hash not approved");
        await executeContractCallWithSigners(safe, signLib, "signMessage", [rawHash], [u1, u2], true);
        expect(await validator.isValidSignature.staticCall(rawHash, "0x")).to.eq("0x1626ba7e");
    });
});
