package org.bouncycastle.test;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.tls.*;
import org.bouncycastle.tls.crypto.TlsCrypto;
import org.bouncycastle.tls.crypto.impl.bc.BcTlsCrypto;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.Security;
import java.util.List;
import java.util.Vector;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * @author 丁琪
 * @date 2021/9/14
 */
public class DefaultTlsScanClient extends DefaultTlsClient {

    public static final List<ProtocolVersion> SUPPORTED_PROTOCOL_VERSIONS = new CopyOnWriteArrayList<>();
    public static final List<ProtocolVersion> TLCP_PROTOCOL_VERSIONS = new CopyOnWriteArrayList<>();
    private static final ProtocolVersion[] PROTOCOL_VERSIONS;

    static {
        Security.addProvider(new BouncyCastleProvider());
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        TLCP_PROTOCOL_VERSIONS.add(ProtocolVersion.TLCPv11);
        SUPPORTED_PROTOCOL_VERSIONS.add(ProtocolVersion.TLSv13);
        SUPPORTED_PROTOCOL_VERSIONS.add(ProtocolVersion.TLSv12);
        SUPPORTED_PROTOCOL_VERSIONS.add(ProtocolVersion.TLSv11);
        SUPPORTED_PROTOCOL_VERSIONS.add(ProtocolVersion.TLSv10);
        SUPPORTED_PROTOCOL_VERSIONS.add(ProtocolVersion.SSLv3);
        PROTOCOL_VERSIONS = SUPPORTED_PROTOCOL_VERSIONS.toArray(new ProtocolVersion[0]);
    }

    protected String nameData;

    public DefaultTlsScanClient(TlsCrypto crypto, String nameData) {
        super(crypto);
        this.nameData = nameData;
    }

    public DefaultTlsScanClient(TlsCrypto crypto) {
        super(crypto);
    }

    public DefaultTlsScanClient(String nameData) {
        super(new BcTlsCrypto());
        this.nameData = nameData;
    }

    public DefaultTlsScanClient() {
        super(new BcTlsCrypto());
    }

    public String getNameData() {
        return nameData;
    }

    public void setNameData(String nameData) {
        this.nameData = nameData;
    }

    @Override
    public ProtocolVersion[] getSupportedVersions() {
        return PROTOCOL_VERSIONS;
    }

    @Override
    public ProtocolVersion[] getProtocolVersions() {
        return PROTOCOL_VERSIONS;
    }

    @Override
    public TlsAuthentication getAuthentication() throws IOException {
        return new TlsAuthentication() {
            @Override
            public void notifyServerCertificate(TlsServerCertificate tlsServerCertificate) throws IOException {

            }

            @Override
            public TlsCredentials getClientCredentials(CertificateRequest certificateRequest) throws IOException {
                return null;
            }
        };
    }

    @Override
    protected Vector getSNIServerNames() {
        Vector sniServerNames = super.getSNIServerNames();
        if (null != this.getNameData()) {
            if (null == sniServerNames || sniServerNames.isEmpty()) {
                sniServerNames = new Vector();
            }
            ServerName serverName = new ServerName(NameType.host_name, this.getNameData().getBytes(StandardCharsets.UTF_8));
            sniServerNames.add(serverName);
        }
        return sniServerNames;
    }

    @Override
    public Vector getEarlyKeyShareGroups() {
        return super.getEarlyKeyShareGroups();
    }

    @Override
    protected Vector getSupportedSignatureAlgorithms() {
        return super.getSupportedSignatureAlgorithms();
    }
}
