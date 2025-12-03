package org.bouncycastle.tls.test;

import org.bouncycastle.tls.CipherSuite;
import org.bouncycastle.tls.EncryptionAlgorithm;
import org.bouncycastle.tls.KeyExchangeAlgorithm;
import org.bouncycastle.tls.MACAlgorithm;
import org.bouncycastle.tls.ProtocolVersion;
import org.bouncycastle.tls.TlsUtils;

import junit.framework.TestCase;

/**
 * Test case for TLCP (Transport Layer Cryptographic Protocol) support.
 * TLCP is defined by GB/T 38636-2020.
 */
public class TLCPProtocolVersionTest
    extends TestCase
{
    public void testTLCPv11Version()
    {
        // Test TLCP protocol version constant
        assertNotNull(ProtocolVersion.TLCPv11);
        assertEquals(0x0101, ProtocolVersion.TLCPv11.getFullVersion());
        assertEquals(0x01, ProtocolVersion.TLCPv11.getMajorVersion());
        assertEquals(0x01, ProtocolVersion.TLCPv11.getMinorVersion());
        assertEquals("TLCP 1.1", ProtocolVersion.TLCPv11.getName());
    }

    public void testTLCPProtocolVersionGet()
    {
        // Test that get(1, 1) returns TLCPv11
        ProtocolVersion version = ProtocolVersion.get(0x01, 0x01);
        assertEquals(ProtocolVersion.TLCPv11, version);
    }

    public void testIsTLCP()
    {
        // Test isTLCP method
        assertTrue(ProtocolVersion.TLCPv11.isTLCP());
        assertFalse(ProtocolVersion.TLSv10.isTLCP());
        assertFalse(ProtocolVersion.TLSv11.isTLCP());
        assertFalse(ProtocolVersion.TLSv12.isTLCP());
        assertFalse(ProtocolVersion.TLSv13.isTLCP());
        assertFalse(ProtocolVersion.DTLSv10.isTLCP());
        assertFalse(ProtocolVersion.DTLSv12.isTLCP());
    }

    public void testTLCPEquivalentTLSVersion()
    {
        // TLCP is based on TLS 1.1 structure
        assertEquals(ProtocolVersion.TLSv11, ProtocolVersion.TLCPv11.getEquivalentTLSVersion());
    }

    public void testTLCPCipherSuites()
    {
        // Test TLCP cipher suite constants are defined
        assertEquals(0xE011, CipherSuite.TLCP_ECDHE_SM4_CBC_SM3);
        assertEquals(0xE051, CipherSuite.TLCP_ECDHE_SM4_GCM_SM3);
        assertEquals(0xE013, CipherSuite.TLCP_ECC_SM4_CBC_SM3);
        assertEquals(0xE053, CipherSuite.TLCP_ECC_SM4_GCM_SM3);
        assertEquals(0xE015, CipherSuite.TLCP_IBSDH_SM4_CBC_SM3);
        assertEquals(0xE055, CipherSuite.TLCP_IBSDH_SM4_GCM_SM3);
        assertEquals(0xE017, CipherSuite.TLCP_IBC_SM4_CBC_SM3);
        assertEquals(0xE057, CipherSuite.TLCP_IBC_SM4_GCM_SM3);
        assertEquals(0xE019, CipherSuite.TLCP_RSA_SM4_CBC_SM3);
        assertEquals(0xE059, CipherSuite.TLCP_RSA_SM4_GCM_SM3);
        assertEquals(0xE01C, CipherSuite.TLCP_RSA_SM4_CBC_SHA256);
        assertEquals(0xE05C, CipherSuite.TLCP_RSA_SM4_GCM_SHA256);
    }

    public void testTLCPKeyExchangeAlgorithm()
    {
        // Test key exchange algorithm for TLCP cipher suites
        assertEquals(KeyExchangeAlgorithm.ECDHE_ECDSA, TlsUtils.getKeyExchangeAlgorithm(CipherSuite.TLCP_ECDHE_SM4_CBC_SM3));
        assertEquals(KeyExchangeAlgorithm.ECDHE_ECDSA, TlsUtils.getKeyExchangeAlgorithm(CipherSuite.TLCP_ECDHE_SM4_GCM_SM3));
        assertEquals(KeyExchangeAlgorithm.SM2, TlsUtils.getKeyExchangeAlgorithm(CipherSuite.TLCP_ECC_SM4_CBC_SM3));
        assertEquals(KeyExchangeAlgorithm.SM2, TlsUtils.getKeyExchangeAlgorithm(CipherSuite.TLCP_ECC_SM4_GCM_SM3));
        assertEquals(KeyExchangeAlgorithm.SM2, TlsUtils.getKeyExchangeAlgorithm(CipherSuite.TLCP_IBSDH_SM4_CBC_SM3));
        assertEquals(KeyExchangeAlgorithm.SM2, TlsUtils.getKeyExchangeAlgorithm(CipherSuite.TLCP_IBSDH_SM4_GCM_SM3));
        assertEquals(KeyExchangeAlgorithm.SM2, TlsUtils.getKeyExchangeAlgorithm(CipherSuite.TLCP_IBC_SM4_CBC_SM3));
        assertEquals(KeyExchangeAlgorithm.SM2, TlsUtils.getKeyExchangeAlgorithm(CipherSuite.TLCP_IBC_SM4_GCM_SM3));
        assertEquals(KeyExchangeAlgorithm.RSA, TlsUtils.getKeyExchangeAlgorithm(CipherSuite.TLCP_RSA_SM4_CBC_SM3));
        assertEquals(KeyExchangeAlgorithm.RSA, TlsUtils.getKeyExchangeAlgorithm(CipherSuite.TLCP_RSA_SM4_GCM_SM3));
        assertEquals(KeyExchangeAlgorithm.RSA, TlsUtils.getKeyExchangeAlgorithm(CipherSuite.TLCP_RSA_SM4_CBC_SHA256));
        assertEquals(KeyExchangeAlgorithm.RSA, TlsUtils.getKeyExchangeAlgorithm(CipherSuite.TLCP_RSA_SM4_GCM_SHA256));
    }

    public void testTLCPEncryptionAlgorithm()
    {
        // Test encryption algorithm for TLCP cipher suites
        assertEquals(EncryptionAlgorithm.SM4_CBC, TlsUtils.getEncryptionAlgorithm(CipherSuite.TLCP_ECDHE_SM4_CBC_SM3));
        assertEquals(EncryptionAlgorithm.SM4_GCM, TlsUtils.getEncryptionAlgorithm(CipherSuite.TLCP_ECDHE_SM4_GCM_SM3));
        assertEquals(EncryptionAlgorithm.SM4_CBC, TlsUtils.getEncryptionAlgorithm(CipherSuite.TLCP_ECC_SM4_CBC_SM3));
        assertEquals(EncryptionAlgorithm.SM4_GCM, TlsUtils.getEncryptionAlgorithm(CipherSuite.TLCP_ECC_SM4_GCM_SM3));
        assertEquals(EncryptionAlgorithm.SM4_CBC, TlsUtils.getEncryptionAlgorithm(CipherSuite.TLCP_IBSDH_SM4_CBC_SM3));
        assertEquals(EncryptionAlgorithm.SM4_GCM, TlsUtils.getEncryptionAlgorithm(CipherSuite.TLCP_IBSDH_SM4_GCM_SM3));
        assertEquals(EncryptionAlgorithm.SM4_CBC, TlsUtils.getEncryptionAlgorithm(CipherSuite.TLCP_IBC_SM4_CBC_SM3));
        assertEquals(EncryptionAlgorithm.SM4_GCM, TlsUtils.getEncryptionAlgorithm(CipherSuite.TLCP_IBC_SM4_GCM_SM3));
        assertEquals(EncryptionAlgorithm.SM4_CBC, TlsUtils.getEncryptionAlgorithm(CipherSuite.TLCP_RSA_SM4_CBC_SM3));
        assertEquals(EncryptionAlgorithm.SM4_GCM, TlsUtils.getEncryptionAlgorithm(CipherSuite.TLCP_RSA_SM4_GCM_SM3));
        assertEquals(EncryptionAlgorithm.SM4_CBC, TlsUtils.getEncryptionAlgorithm(CipherSuite.TLCP_RSA_SM4_CBC_SHA256));
        assertEquals(EncryptionAlgorithm.SM4_GCM, TlsUtils.getEncryptionAlgorithm(CipherSuite.TLCP_RSA_SM4_GCM_SHA256));
    }

    public void testTLCPMACAlgorithm()
    {
        // Test MAC algorithm for TLCP cipher suites
        assertEquals(MACAlgorithm.hmac_sm3, TlsUtils.getMACAlgorithm(CipherSuite.TLCP_ECDHE_SM4_CBC_SM3));
        assertEquals(MACAlgorithm._null, TlsUtils.getMACAlgorithm(CipherSuite.TLCP_ECDHE_SM4_GCM_SM3)); // GCM has no MAC
        assertEquals(MACAlgorithm.hmac_sm3, TlsUtils.getMACAlgorithm(CipherSuite.TLCP_ECC_SM4_CBC_SM3));
        assertEquals(MACAlgorithm._null, TlsUtils.getMACAlgorithm(CipherSuite.TLCP_ECC_SM4_GCM_SM3)); // GCM has no MAC
        assertEquals(MACAlgorithm.hmac_sm3, TlsUtils.getMACAlgorithm(CipherSuite.TLCP_RSA_SM4_CBC_SM3));
        assertEquals(MACAlgorithm._null, TlsUtils.getMACAlgorithm(CipherSuite.TLCP_RSA_SM4_GCM_SM3)); // GCM has no MAC
        assertEquals(MACAlgorithm.hmac_sha256, TlsUtils.getMACAlgorithm(CipherSuite.TLCP_RSA_SM4_CBC_SHA256));
        assertEquals(MACAlgorithm._null, TlsUtils.getMACAlgorithm(CipherSuite.TLCP_RSA_SM4_GCM_SHA256)); // GCM has no MAC
    }

    public void testTLCPMinimumVersion()
    {
        // Test minimum version for TLCP cipher suites is TLCPv11
        assertEquals(ProtocolVersion.TLCPv11, TlsUtils.getMinimumVersion(CipherSuite.TLCP_ECDHE_SM4_CBC_SM3));
        assertEquals(ProtocolVersion.TLCPv11, TlsUtils.getMinimumVersion(CipherSuite.TLCP_ECDHE_SM4_GCM_SM3));
        assertEquals(ProtocolVersion.TLCPv11, TlsUtils.getMinimumVersion(CipherSuite.TLCP_ECC_SM4_CBC_SM3));
        assertEquals(ProtocolVersion.TLCPv11, TlsUtils.getMinimumVersion(CipherSuite.TLCP_ECC_SM4_GCM_SM3));
        assertEquals(ProtocolVersion.TLCPv11, TlsUtils.getMinimumVersion(CipherSuite.TLCP_RSA_SM4_CBC_SM3));
        assertEquals(ProtocolVersion.TLCPv11, TlsUtils.getMinimumVersion(CipherSuite.TLCP_RSA_SM4_GCM_SM3));
    }

    public void testTLCPHelperMethods()
    {
        // Test TlsUtils.isTLCP method
        assertTrue(TlsUtils.isTLCP(ProtocolVersion.TLCPv11));
        assertFalse(TlsUtils.isTLCP(ProtocolVersion.TLSv11));
        assertFalse(TlsUtils.isTLCP(ProtocolVersion.TLSv12));
        assertFalse(TlsUtils.isTLCP((ProtocolVersion)null));
    }

    public void testGetEarliestAndLatestTLCP()
    {
        // Test getEarliestTLCP and getLatestTLCP methods
        ProtocolVersion[] versions = new ProtocolVersion[] {
            ProtocolVersion.TLSv10,
            ProtocolVersion.TLSv11,
            ProtocolVersion.TLCPv11,
            ProtocolVersion.TLSv12
        };

        assertEquals(ProtocolVersion.TLCPv11, ProtocolVersion.getEarliestTLCP(versions));
        assertEquals(ProtocolVersion.TLCPv11, ProtocolVersion.getLatestTLCP(versions));

        // Test with no TLCP versions
        ProtocolVersion[] tlsOnly = new ProtocolVersion[] {
            ProtocolVersion.TLSv10,
            ProtocolVersion.TLSv11
        };

        assertNull(ProtocolVersion.getEarliestTLCP(tlsOnly));
        assertNull(ProtocolVersion.getLatestTLCP(tlsOnly));
    }

    public void testHmacSm3MACAlgorithm()
    {
        // Test HMAC-SM3 MAC algorithm
        assertEquals(6, MACAlgorithm.hmac_sm3);
        assertEquals("hmac_sm3", MACAlgorithm.getName(MACAlgorithm.hmac_sm3));
        assertTrue(MACAlgorithm.isHMAC(MACAlgorithm.hmac_sm3));
    }
}
