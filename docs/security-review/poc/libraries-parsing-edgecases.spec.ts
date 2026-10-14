import { expect } from "chai";
import hre, { ethers } from "hardhat";
import {
    deployContractFromSource,
    getMultiSend,
    getMultiSendCallOnly,
    getSafe,
    getDelegateCaller,
    getSignMessageLib,
    getSimulateTxAccessor,
} from "../../../test/utils/setup";
import { buildSafeTransaction, executeTxWithSigners } from "../../../src/utils/execution";

// Security review PoC (run with: AUDIT_LOCAL_SOLC=1 npx hardhat test docs/security-review/poc/libraries-parsing-edgecases.spec.ts).
// Exercises the packed-encoding parser of MultiSend / MultiSendCallOnly and a few singleton-direct-call paths.
describe("Security review PoC: library parsing edge cases [@skip-on-coverage]", () => {
    const setupTests = hre.deployments.createFixture(async ({ deployments }) => {
        await deployments.fixture();
        const signers = await hre.ethers.getSigners();
        const [user1] = signers;
        const recorderSource = `
            contract Recorder {
                uint256 public calls;
                uint256 public lastLen;
                bytes32 public lastHash;
                fallback() external payable {
                    calls++;
                    lastLen = msg.data.length;
                    lastHash = keccak256(msg.data);
                }
                receive() external payable {
                    calls++;
                    lastLen = 0;
                    lastHash = keccak256("");
                }
            }`;
        const fakeErrorSource = `
            contract FakeError {
                // Successful call whose *return data* happens to be an ABI encoded Error(string).
                fallback() external {
                    bytes memory r = abi.encodeWithSignature("Error(string)", "NOT A REVERT");
                    assembly { return(add(r, 0x20), mload(r)) }
                }
            }`;
        return {
            safe: await getSafe({ owners: [user1.address] }),
            multiSend: await getMultiSend(),
            multiSendCallOnly: await getMultiSendCallOnly(),
            delegateCaller: await getDelegateCaller(),
            signMessageLib: await getSignMessageLib(),
            accessor: await getSimulateTxAccessor(),
            recorder: await deployContractFromSource(user1, recorderSource),
            fakeError: await deployContractFromSource(user1, fakeErrorSource),
            signers,
        };
    });

    const packEntry = (op: number, to: string, value: bigint, declaredLen: number, data: string) =>
        ethers.solidityPacked(["uint8", "address", "uint256", "uint256", "bytes"], [op, to, value, declaredLen, data]).slice(2);

    it("over-long dataLength reads zero-filled memory past the array (no garbage) and calls `to` with zero padding", async () => {
        const { safe, multiSend, recorder, signers } = await setupTests();
        const [user1] = signers;
        const recorderAddress = await recorder.getAddress();
        // Declares 68 bytes of data, but only 4 are provided.
        const packed = "0x" + packEntry(0, recorderAddress, 0n, 68, "0xdeadbeef");
        const tx = buildSafeTransaction({
            to: await multiSend.getAddress(),
            data: multiSend.interface.encodeFunctionData("multiSend", [packed]),
            operation: 1,
            nonce: await safe.nonce(),
        });
        await executeTxWithSigners(safe, tx, [user1]);
        expect(await recorder.calls()).to.eq(1n);
        expect(await recorder.lastLen()).to.eq(68n);
        expect(await recorder.lastHash()).to.eq(ethers.keccak256("0xdeadbeef" + "00".repeat(64)));
    });

    it("invalid operation reverts with the *previous* sub-call's return data (stale returndata)", async () => {
        const { multiSend, multiSendCallOnly, delegateCaller, fakeError, signers } = await setupTests();
        const [, user2] = signers;
        const fakeErrorAddress = await fakeError.getAddress();
        const packed = "0x" + packEntry(0, fakeErrorAddress, 0n, 4, "0xdeadbeef") + packEntry(2, user2.address, 0n, 0, "0x");
        for (const lib of [multiSend, multiSendCallOnly]) {
            const data = lib.interface.encodeFunctionData("multiSend", [packed]);
            // Looks like `revert("NOT A REVERT")` although no sub-call reverted; the invalid op is the real cause.
            await expect(delegateCaller.makeDelegatecall.staticCall(await lib.getAddress(), data)).to.be.revertedWith("NOT A REVERT");
        }
        // Single invalid-op entry with no prior call: empty revert data.
        const packedSingle = "0x" + packEntry(2, user2.address, 0n, 0, "0x");
        await expect(
            delegateCaller.makeDelegatecall.staticCall(
                await multiSend.getAddress(),
                multiSend.interface.encodeFunctionData("multiSend", [packedSingle]),
            ),
        ).to.be.revertedWithoutReason();
    });

    it("trailing bytes shorter than 32 are silently ignored; 33..84 trailing bytes are parsed as a zero-filled entry", async () => {
        const { safe, multiSend, recorder, signers } = await setupTests();
        const [user1] = signers;
        const recorderAddress = await recorder.getAddress();
        const good = packEntry(0, recorderAddress, 0n, 4, "0xdeadbeef");

        // 31 trailing 0xff bytes -> loop exits since i (0x20 + 89) >= length (120).
        let packed = "0x" + good + "ff".repeat(31);
        let tx = buildSafeTransaction({
            to: await multiSend.getAddress(),
            data: multiSend.interface.encodeFunctionData("multiSend", [packed]),
            operation: 1,
            nonce: await safe.nonce(),
        });
        await executeTxWithSigners(safe, tx, [user1]);
        expect(await recorder.calls()).to.eq(1n);

        // 40 trailing bytes [op=0][to=recorder][19 zero bytes]: parsed as entry with value=0, dataLength=0 (zero fill).
        packed = "0x" + good + "00" + recorderAddress.slice(2) + "00".repeat(19);
        tx = buildSafeTransaction({
            to: await multiSend.getAddress(),
            data: multiSend.interface.encodeFunctionData("multiSend", [packed]),
            operation: 1,
            nonce: await safe.nonce(),
        });
        await executeTxWithSigners(safe, tx, [user1]);
        expect(await recorder.calls()).to.eq(3n);
        expect(await recorder.lastLen()).to.eq(0n);
    });

    it("huge dataLength cannot wrap the cursor: the call itself runs out of gas and the batch reverts", async () => {
        const { multiSend, delegateCaller, recorder } = await setupTests();
        const recorderAddress = await recorder.getAddress();
        const huge = (1n << 256n) - 0x55n - 0x20n; // would wrap i back to a small value if the call survived
        const packed = "0x" + ethers.solidityPacked(["uint8", "address", "uint256", "uint256"], [0, recorderAddress, 0, huge]).slice(2);
        await expect(
            delegateCaller.makeDelegatecall.staticCall(
                await multiSend.getAddress(),
                multiSend.interface.encodeFunctionData("multiSend", [packed]),
                { gasLimit: 5_000_000 },
            ),
        ).to.be.reverted;
    });

    it("getStorageAt with a length that overflows `length << 5` reverts (view, OOG) instead of returning", async () => {
        const { safe } = await setupTests();
        await expect(safe.getStorageAt(0, (1n << 251n) + 1n, { gasLimit: 30_000_000 })).to.be.reverted;
    });

    it("direct calls on singletons: MultiSendCallOnly executes with itself as msg.sender; SignMessageLib/SimulateTxAccessor/MultiSend revert", async () => {
        const { multiSend, multiSendCallOnly, signMessageLib, accessor, recorder, signers } = await setupTests();
        const [user1] = signers;
        const recorderAddress = await recorder.getAddress();
        const packed = "0x" + packEntry(0, recorderAddress, 1n, 0, "0x");
        // MultiSendCallOnly has no delegatecall guard: anyone can route ETH through the singleton.
        await multiSendCallOnly.connect(user1).multiSend(packed, { value: 1n });
        expect(await recorder.calls()).to.eq(1n);
        expect(await hre.ethers.provider.getBalance(recorderAddress)).to.eq(1n);
        await expect(multiSend.multiSend(packed)).to.be.revertedWith("MultiSend should only be called via delegatecall");
        await expect(signMessageLib.signMessage("0x1234")).to.be.reverted;
        await expect(accessor.simulate(recorderAddress, 0, "0x", 0)).to.be.revertedWith(
            "SimulateTxAccessor should only be called via delegatecall",
        );
    });
});
