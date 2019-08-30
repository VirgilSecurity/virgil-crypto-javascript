import { NodeBuffer } from "@virgilsecurity/data-utils";
import { expect } from "chai";

import { initPythia, VirgilBrainKeyCrypto, VirgilPythiaCrypto } from "../index";
import data from "./data.json";

const DEBLINDED_PASSWORD = NodeBuffer.from(data.kDeblindedPassword, "hex");

const PASSWORD = "password";
const TRANSFORMATION_KEY_ID = NodeBuffer.from(data.kTransformationKeyID);
const TWEAK = NodeBuffer.from(data.kTweek);
const PYTHIA_SECRET = NodeBuffer.from(data.kPythiaSecret);
const PYTHIA_SCOPE_SECRET = NodeBuffer.from(data.kPythiaScopeSecret);

describe("VirgilBrainKeyCrypto", () => {
  let virgilBrainKeyCrypto: VirgilBrainKeyCrypto;
  let virgilPythiaCrypto: VirgilPythiaCrypto;

  before(async () => {
    await initPythia();
  });

  beforeEach(() => {
    virgilBrainKeyCrypto = new VirgilBrainKeyCrypto();
    virgilPythiaCrypto = new VirgilPythiaCrypto();
  });

  describe("blind", () => {
    it("returns `blindedPassword` and `blindingSecret`", () => {
      const result = virgilBrainKeyCrypto.blind("password");
      expect(Object.keys(result)).to.have.length(2);
      expect(result.blindedPassword).to.be.instanceOf(NodeBuffer);
      expect(result.blindingSecret).to.be.instanceOf(NodeBuffer);
    });
  });

  describe("deblind", () => {
    it("produces the same result for multiple iterations", () => {
      for (let i = 0; i < 10; i += 1) {
        const { blindingSecret, blindedPassword } = virgilBrainKeyCrypto.blind(
          PASSWORD
        );
        const {
          privateKey: transformationPrivateKey
        } = virgilPythiaCrypto.computeTransformationKeyPair({
          transformationKeyId: TRANSFORMATION_KEY_ID,
          pythiaSecret: PYTHIA_SECRET,
          pythiaScopeSecret: PYTHIA_SCOPE_SECRET
        });
        const { transformedPassword } = virgilPythiaCrypto.transform({
          blindedPassword,
          transformationPrivateKey,
          tweak: TWEAK
        });
        const result = virgilBrainKeyCrypto.deblind({
          transformedPassword,
          blindingSecret
        });
        expect(result.equals(DEBLINDED_PASSWORD)).to.be.true;
      }
    });
  });
});
