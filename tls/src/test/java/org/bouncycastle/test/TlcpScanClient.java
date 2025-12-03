package org.bouncycastle.test;

import org.bouncycastle.tls.CipherSuite;
import org.bouncycastle.tls.ProtocolVersion;
import org.bouncycastle.tls.crypto.TlsCrypto;

import java.io.IOException;
import java.security.Security;

/**
 * @author 丁琪
 * @date 2021/9/14
 */
public class TlcpScanClient extends DefaultTlsScanClient {

    private static final ProtocolVersion[] PROTOCOL_VERSIONS = TLCP_PROTOCOL_VERSIONS.toArray(new ProtocolVersion[0]);
    private static final int[] DEFAULT_CIPHER_SUITES = new int[]{
        /*
         * GMSSL 1.1
         */
        CipherSuite.TLCP_ECC_SM4_GCM_SM3,
        CipherSuite.TLCP_ECC_SM4_CBC_SM3,
    };

    public TlcpScanClient(TlsCrypto crypto, String nameData) {
        super(crypto, nameData);
    }

    public TlcpScanClient(TlsCrypto crypto) {
        super(crypto);
    }


    public TlcpScanClient(String nameData) {
        super(nameData);
    }

    public TlcpScanClient() {
        super();
    }


    @Override
    public ProtocolVersion[] getSupportedVersions() {
        return TlcpScanClient.PROTOCOL_VERSIONS;
    }

    @Override
    public ProtocolVersion[] getProtocolVersions() {
        return TlcpScanClient.PROTOCOL_VERSIONS;
    }


    @Override
    protected int[] getSupportedCipherSuites() {
        return TlcpScanClient.DEFAULT_CIPHER_SUITES;
    }

    /**
     * GMSSL Client generate random struct should be
     * struct
     * {
     * unit32 gmt_unix_time;
     * opaque random_bytes[28];
     * }
     *
     * @return true - use GMTUnixTime
     */
    @Override
    public boolean shouldUseGMTUnixTime() {
        return true;
    }

    @Override
    public void notifySecureRenegotiation(boolean secureRenegotiation) throws IOException {
    }
}
