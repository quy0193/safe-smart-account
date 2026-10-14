import { expect } from "chai";
import { deployments, ethers } from "hardhat";
import { AddressZero } from "@ethersproject/constants";
import { getSafe, deployContractFromSource } from "../../../test/utils/setup";
import {
    buildSignatureBytes,
    buildContractSignature,
    buildSafeTransaction,
    calculateSafeTransactionHash,
    executeTx,
} from "../../../src/utils/execution";
import { chainId } from "../../../test/utils/encoding";

// Security review PoC for the post-audit-diff lens (#1115 SecuredSignatureValidator).
// Run with: npx hardhat test docs/security-review/poc/post-audit-erc1271-strict-return.spec.ts --network hardhat
//
// Each validator returns crafted raw return data from `isValidSignature(bytes32,bytes)`.
// `word` is the 32-byte word stored at memory 0, `len` is the number of bytes returned.
const MAGIC_LEFT = "0x1626ba7e00000000000000000000000000000000000000000000000000000000";
const MAGIC_LEFT_DIRTY = "0x1626ba7e00000000000000000000000000000000000000000000000000000001";
const MAGIC_RIGHT = "0x000000000000000000000000000000000000000000000000000000001626ba7e";

const validatorSource = (word: string, len: number) => `
contract Test {
    function isValidSignature(bytes32, bytes memory) external pure returns (bytes4) {
        assembly {
            mstore(0, ${word})
            mstore(32, ${word})
            return(0, ${len})
        }
    }
}`;

const gasBurnerSource = `
contract Test {
    function isValidSignature(bytes32, bytes memory) external pure returns (bytes4) {
        assembly {
            for {} 1 {} {}
        }
    }
}`;

// A caller compiled with the same solc (0.7.6, legacy ABI coder) that performs the pre-#1115
// high-level call `ISignatureValidator(owner).isValidSignature(...) == EIP1271_MAGIC_VALUE`.
const legacyCallerSource = `
interface ISV { function isValidSignature(bytes32, bytes memory) external view returns (bytes4); }
contract Test {
    function legacyCheck(address v, bytes32 h, bytes memory sig) external view returns (bool) {
        return ISV(v).isValidSignature(h, sig) == bytes4(0x1626ba7e);
    }
}`;

describe("Security review PoC: #1115 strict ERC-1271 return check", () => {
    const setupTests = deployments.createFixture(async ({ deployments }) => {
        await deployments.fixture();
        const signers = await ethers.getSigners();
        const [deployer] = signers;
        const legacy = await deployContractFromSource(deployer, legacyCallerSource);
        return { signers, deployer, legacy };
    });

    const cases: { name: string; word: string; len: number; newValid: boolean; legacy: "true" | "false" | "revert" }[] = [
        { name: "exactly 32 bytes, magic left-aligned (abi.encode(bytes4))", word: MAGIC_LEFT, len: 32, newValid: true, legacy: "true" },
        { name: "33 bytes (one trailing byte)", word: MAGIC_LEFT, len: 33, newValid: false, legacy: "true" },
        { name: "64 bytes (trailing word)", word: MAGIC_LEFT, len: 64, newValid: false, legacy: "true" },
        { name: "31 bytes (short)", word: MAGIC_LEFT, len: 31, newValid: false, legacy: "revert" },
        { name: "4 bytes (bare bytes4)", word: MAGIC_LEFT, len: 4, newValid: false, legacy: "revert" },
        { name: "0 bytes", word: MAGIC_LEFT, len: 0, newValid: false, legacy: "revert" },
        { name: "32 bytes, dirty low bits", word: MAGIC_LEFT_DIRTY, len: 32, newValid: false, legacy: "true" },
        { name: "32 bytes, magic right-aligned (uint32 encoding)", word: MAGIC_RIGHT, len: 32, newValid: false, legacy: "false" },
    ];

    for (const c of cases) {
        it(`checkNSignatures: ${c.name} => ${c.newValid ? "valid" : "GS024"}; legacy high-level call => ${c.legacy}`, async () => {
            const { deployer, legacy } = await setupTests();
            const validator = await deployContractFromSource(deployer, validatorSource(c.word, c.len));
            const validatorAddress = await validator.getAddress();

            const safe = await getSafe({ owners: [validatorAddress], threshold: 1 });
            const safeAddress = await safe.getAddress();
            const tx = buildSafeTransaction({ to: safeAddress, nonce: await safe.nonce() });
            const txHash = calculateSafeTransactionHash(safeAddress, tx, await chainId());
            const signatures = buildSignatureBytes([buildContractSignature(validatorAddress, "0x")]);

            const check = safe["checkNSignatures(address,bytes32,bytes,uint256)"](AddressZero, txHash, signatures, 1);
            if (c.newValid) {
                await expect(check).to.not.be.reverted;
            } else {
                await expect(check).to.be.revertedWith("GS024");
            }

            // What the pre-#1115 code path would have done with the same return data.
            const legacyCall = legacy.legacyCheck(validatorAddress, txHash, "0x");
            if (c.legacy === "revert") {
                await expect(legacyCall).to.be.reverted;
            } else {
                expect(await legacyCall).to.eq(c.legacy === "true");
            }
        });
    }

    it("EOA used as a v=0 contract signer => GS024 (not an empty revert as before)", async () => {
        const {
            signers: [user1, user2],
        } = await setupTests();
        const safe = await getSafe({ owners: [user1.address], threshold: 1 });
        const safeAddress = await safe.getAddress();
        const tx = buildSafeTransaction({ to: safeAddress, nonce: await safe.nonce() });
        const txHash = calculateSafeTransactionHash(safeAddress, tx, await chainId());
        // user2 (an EOA with no code) is not even an owner; the contract-signature check runs before GS026.
        const signatures = buildSignatureBytes([buildContractSignature(user2.address, "0x")]);
        await expect(safe["checkNSignatures(address,bytes32,bytes,uint256)"](AddressZero, txHash, signatures, 1)).to.be.revertedWith(
            "GS024",
        );
    });

    it("validator that burns all forwarded gas => GS024 from the 1/64 reserve, not a bare OOG", async () => {
        const { deployer } = await setupTests();
        const validator = await deployContractFromSource(deployer, gasBurnerSource);
        const validatorAddress = await validator.getAddress();
        const safe = await getSafe({ owners: [validatorAddress], threshold: 1 });
        const safeAddress = await safe.getAddress();
        const tx = buildSafeTransaction({ to: safeAddress, nonce: await safe.nonce() });
        const txHash = calculateSafeTransactionHash(safeAddress, tx, await chainId());
        const signatures = buildSignatureBytes([buildContractSignature(validatorAddress, "0x")]);
        await expect(
            safe["checkNSignatures(address,bytes32,bytes,uint256)"](AddressZero, txHash, signatures, 1, { gasLimit: 3_000_000 }),
        ).to.be.revertedWith("GS024");
    });

    it("execTransaction with a 33-byte-returning owner reverts as a whole: nonce is not consumed", async () => {
        const {
            deployer,
            signers: [, user2],
        } = await setupTests();
        const validator = await deployContractFromSource(deployer, validatorSource(MAGIC_LEFT, 33));
        const validatorAddress = await validator.getAddress();
        const safe = await getSafe({ owners: [validatorAddress], threshold: 1 });
        const safeAddress = await safe.getAddress();
        const nonceBefore = await safe.nonce();
        const tx = buildSafeTransaction({ to: safeAddress, nonce: nonceBefore });
        const signatures = [{ signer: validatorAddress, data: "0x", dynamic: true } as const];
        await expect(executeTx(safe.connect(user2), tx, signatures)).to.be.revertedWith("GS024");
        expect(await safe.nonce()).to.eq(nonceBefore);
    });

    it("a Safe (CompatibilityFallbackHandler) as ERC-1271 owner still validates: 32-byte return path", async () => {
        const {
            signers: [user1, user2],
        } = await setupTests();
        const { getCompatFallbackHandler } = await import("../../../test/utils/setup");
        const { calculateSafeMessageHash, signHash } = await import("../../../src/utils/execution");
        const handler = await getCompatFallbackHandler();
        const handlerAddress = await handler.getAddress();
        const signerSafe = await getSafe({ owners: [user1.address], threshold: 1, fallbackHandler: handlerAddress });
        const signerSafeAddress = await signerSafe.getAddress();
        const safe = await getSafe({ owners: [signerSafeAddress], threshold: 1 });
        const safeAddress = await safe.getAddress();
        const tx = buildSafeTransaction({ to: safeAddress, nonce: await safe.nonce() });
        const txHash = calculateSafeTransactionHash(safeAddress, tx, await chainId());
        const msgHash = calculateSafeMessageHash(signerSafeAddress, txHash, await chainId());
        const ownerSig = await signHash(user1, msgHash);
        const signatures = buildSignatureBytes([buildContractSignature(signerSafeAddress, ownerSig.data)]);
        await expect(safe["checkNSignatures(address,bytes32,bytes,uint256)"](AddressZero, txHash, signatures, 1)).to.not.be.reverted;
        // Raw return data of the nested Safe's isValidSignature is exactly 32 bytes.
        const raw = await ethers.provider.call({
            to: signerSafeAddress,
            data: handler.interface.encodeFunctionData("isValidSignature", [txHash, ownerSig.data]),
        });
        expect(raw).to.eq(MAGIC_LEFT);
        void user2;
    });
});
