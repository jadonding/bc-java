package org.bouncycastle.tls.crypto.impl.bc;

import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.ParametersWithID;
import org.bouncycastle.crypto.signers.SM2Signer;
import org.bouncycastle.tls.DigitallySigned;
import org.bouncycastle.tls.SignatureAlgorithm;
import org.bouncycastle.tls.SignatureAndHashAlgorithm;
import org.bouncycastle.util.Strings;

/**
 * Implementation class for SM2 signature verification for TLCP/GMSSL.
 */
public class BcTlsSM2Verifier
        extends BcTlsVerifier {
    public BcTlsSM2Verifier(BcTlsCrypto crypto, ECPublicKeyParameters publicKey) {
        super(crypto, publicKey);
    }

    public boolean verifyRawSignature(DigitallySigned digitallySigned, byte[] hash) {
        SignatureAndHashAlgorithm algorithm = digitallySigned.getAlgorithm();
        if (algorithm != null && algorithm.getSignature() != SignatureAlgorithm.ecdsa) {
            throw new IllegalStateException("Invalid algorithm: " + algorithm);
        }

        /*
         * GB/T 38636-2020 (TLCP) - SM2 signature verification
         * Use default identifier for TLCP
         */
        byte[] identifier = Strings.toByteArray("1234567812345678");
        ParametersWithID parametersWithID = new ParametersWithID(publicKey, identifier);

        SM2Signer verifier = new SM2Signer();
        verifier.init(false, parametersWithID);

        // SM2Signer.verifySignature takes the hash and then processes it
        verifier.update(hash, 0, hash.length);

        return verifier.verifySignature(digitallySigned.getSignature());
    }
}
