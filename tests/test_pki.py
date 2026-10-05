import unittest
import os
import sys
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding

# Add backend to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

class TestPKIInfrastructure(unittest.TestCase):

    def setUp(self):
        # Base path to PKI
        self.base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'backend'))
        self.pki_dir = os.path.join(self.base_dir, 'pki')
        self.ac1_dir = os.path.join(self.pki_dir, 'AC1')
        self.ac2_dir = os.path.join(self.pki_dir, 'AC2')

    def test_pki_directories_exist(self):
        """Verify that the main PKI directories exist"""
        self.assertTrue(os.path.exists(self.pki_dir), "PKI directory not found")
        self.assertTrue(os.path.exists(self.ac1_dir), "AC1 directory not found")
        self.assertTrue(os.path.exists(self.ac2_dir), "AC2 directory not found")

    def test_ac1_certificate_exists_and_valid(self):
        """Verify AC1 certificate exists and is a valid x509 certificate"""
        cert_path = os.path.join(self.ac1_dir, 'ac1cert.pem')
        self.assertTrue(os.path.exists(cert_path), "AC1 certificate not found")
        
        with open(cert_path, 'rb') as f:
            cert_data = f.read()
            cert = x509.load_pem_x509_certificate(cert_data, default_backend())
            
        # Check basic properties
        self.assertIsInstance(cert, x509.Certificate)
        # AC1 should be self-signed or at least valid. 
        # We can check if subject == issuer for a root CA
        self.assertEqual(cert.subject, cert.issuer, "AC1 should be a Root CA (Subject == Issuer)")

    def test_ac2_certificate_exists_and_signed_by_ac1(self):
        """Verify AC2 certificate exists and is signed by AC1"""
        ac1_cert_path = os.path.join(self.ac1_dir, 'ac1cert.pem')
        ac2_cert_path = os.path.join(self.ac2_dir, 'ac2cert.pem')
        
        self.assertTrue(os.path.exists(ac2_cert_path), "AC2 certificate not found")
        
        # Load AC1 cert (Issuer)
        with open(ac1_cert_path, 'rb') as f:
            ac1_cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            ac1_public_key = ac1_cert.public_key()
            
        # Load AC2 cert (Subject)
        with open(ac2_cert_path, 'rb') as f:
            ac2_cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            
        # Verify AC2 is issued by AC1
        self.assertEqual(ac2_cert.issuer, ac1_cert.subject, "AC2 Issuer should be AC1 Subject")
        
        # Verify signature
        try:
            ac1_public_key.verify(
                ac2_cert.signature,
                ac2_cert.tbs_certificate_bytes,
                padding.PKCS1v15(), # x509 certificates usually use PKCS1v15 for signature
                ac2_cert.signature_hash_algorithm
            )
        except Exception as e:
            self.fail(f"AC2 certificate signature verification failed: {e}")

    def test_crl_directories_exist(self):
        """Verify CRL directories exist for both CAs"""
        self.assertTrue(os.path.exists(os.path.join(self.ac1_dir, 'crls')), "AC1 CRLs dir missing")
        self.assertTrue(os.path.exists(os.path.join(self.ac2_dir, 'crls')), "AC2 CRLs dir missing")

    def test_user_certificates_exist_and_valid(self):
        """Verify that existing user certificates are valid and signed by AC2"""
        users_dir = os.path.join(self.pki_dir, 'usuarios')
        if not os.path.exists(users_dir):
            return # Skip if no users directory

        # Load AC2 public key for verification
        ac2_cert_path = os.path.join(self.ac2_dir, 'ac2cert.pem')
        with open(ac2_cert_path, 'rb') as f:
            ac2_cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            ac2_public_key = ac2_cert.public_key()

        # Check known users
        known_users = ['NachinMonin', 'manchadin', 'mateu_27']
        for user in known_users:
            user_dir = os.path.join(users_dir, user)
            if os.path.isdir(user_dir):
                cert_path = os.path.join(user_dir, 'certificate.pem')
                self.assertTrue(os.path.exists(cert_path), f"Certificate for {user} not found")
                
                with open(cert_path, 'rb') as f:
                    user_cert = x509.load_pem_x509_certificate(f.read(), default_backend())
                
                # Verify issuer is AC2
                self.assertEqual(user_cert.issuer, ac2_cert.subject, f"User {user} should be issued by AC2")
                
                # Verify signature
                try:
                    ac2_public_key.verify(
                        user_cert.signature,
                        user_cert.tbs_certificate_bytes,
                        padding.PKCS1v15(),
                        user_cert.signature_hash_algorithm
                    )
                except Exception as e:
                    self.fail(f"Signature verification failed for user {user}: {e}")


if __name__ == '__main__':
    from cryptography.hazmat.primitives.asymmetric import padding
    unittest.main()
