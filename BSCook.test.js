import { expect } from "chai";
import hre from "hardhat";

describe("BSCook Core Smart Contracts", function () {
  let ethers;

  before(async function () {
    ethers = hre.ethers;
  });

  describe("BSCookToken", function () {
    it("Should deploy token implementation and verify default locked state", async function () {
      const TokenFactory = await ethers.getContractFactory("BSCookToken");
      const token = await TokenFactory.deploy();
      await token.waitForDeployment();

      // Master implementation constructor initializes to empty string and locked
      expect(await token.name()).to.equal("");
      expect(await token.symbol()).to.equal("");
      expect(await token.decimals()).to.equal(18);
    });
  });

  describe("BSCookTimelock", function () {
    it("Should reject deployment with delay less than 12 hours", async function () {
      const TimelockFactory = await ethers.getContractFactory("BSCookTimelock");
      const shortDelay = 3600; // 1 hour (less than 12 hours)

      await expect(
        TimelockFactory.deploy(shortDelay, [], [], ethers.ZeroAddress)
      ).to.be.revertedWith("Delay too short");
    });

    it("Should reject deployment with delay greater than 48 hours", async function () {
      const TimelockFactory = await ethers.getContractFactory("BSCookTimelock");
      const longDelay = 50 * 3600; // 50 hours

      await expect(
        TimelockFactory.deploy(longDelay, [], [], ethers.ZeroAddress)
      ).to.be.revertedWith("Delay exceeds max 48 hours");
    });

    it("Should succeed deployment with valid 24h delay", async function () {
      const TimelockFactory = await ethers.getContractFactory("BSCookTimelock");
      const validDelay = 24 * 3600; // 24 hours

      const timelock = await TimelockFactory.deploy(validDelay, [], [], ethers.ZeroAddress);
      await timelock.waitForDeployment();

      expect(await timelock.getMinDelay()).to.equal(validDelay);
    });
  });

  describe("BSCookMultiSig", function () {
    it("Should reject deployment with invalid owners or zero threshold", async function () {
      const [signer1, signer2, signer3] = await ethers.getSigners();
      const MultiSigFactory = await ethers.getContractFactory("BSCookMultiSig");

      // Threshold = 0 should revert
      await expect(
        MultiSigFactory.deploy([signer1.address, signer2.address], 0)
      ).to.be.revertedWith("Threshold cannot be zero");

      // Threshold > owners count should revert
      await expect(
        MultiSigFactory.deploy([signer1.address, signer2.address], 3)
      ).to.be.revertedWith("Threshold exceeds owners count");
    });

    it("Should deploy successfully with 2-of-3 threshold", async function () {
      const [signer1, signer2, signer3] = await ethers.getSigners();
      const MultiSigFactory = await ethers.getContractFactory("BSCookMultiSig");

      const multiSig = await MultiSigFactory.deploy(
        [signer1.address, signer2.address, signer3.address],
        2
      );
      await multiSig.waitForDeployment();

      expect(await multiSig.threshold()).to.equal(2);
      expect(await multiSig.isOwner(signer1.address)).to.be.true;
      expect(await multiSig.isOwner(signer2.address)).to.be.true;
      expect(await multiSig.isOwner(signer3.address)).to.be.true;
    });
  });
});
