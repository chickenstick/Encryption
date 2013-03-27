#region - Using Statements -

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

#endregion

namespace Encryption
{
    public sealed class Crypto : IDisposable
    {

        #region - Constants -

        private const HashAlgorithm DEFAULT_HASH_ALGORITHM = HashAlgorithm.SHA1;
        private const KeySize DEFAULT_KEY_SIZE = KeySize.KeySize256;
        private const int DEFAULT_PASSWORD_ITERATIONS = 2;

        #endregion

        #region - Fields -

        private AesManaged _aes;
        private int _passwordIterations;
        private string _password;
        private string _salt;
        private InitialVector _initialVector;

        #endregion

        #region - Constructor -

        /// <summary>
        /// Initializes a new instance of the <see cref="Crypto"/> class.
        /// </summary>
        /// <param name="password">The password.</param>
        /// <param name="salt">The salt.</param>
        public Crypto(string password, string salt)
            : this(password, salt, InitialVector.CreateRandom())
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="Crypto"/> class.
        /// </summary>
        /// <param name="password">The password.</param>
        /// <param name="salt">The salt.</param>
        /// <param name="initialVector">The initial vector.</param>
        public Crypto(string password, string salt, InitialVector initialVector)
        {
            if (string.IsNullOrEmpty(password))
            {
                throw new ArgumentNullException("password");
            }

            if (string.IsNullOrEmpty(salt))
            {
                throw new ArgumentNullException("salt");
            }

            if (initialVector == null)
            {
                throw new ArgumentNullException("initialVector");
            }

            if (!initialVector.IsValid)
            {
                throw new ArgumentException("The initial vector does not have a valid value.", "initialVector");
            }

            _aes = new AesManaged();
            _aes.Mode = CipherMode.CBC;

            this.Password = password;
            this.Salt = salt;

            this.InitialVector = initialVector;
            this.HashAlgorithm = DEFAULT_HASH_ALGORITHM;
            this.KeySize = DEFAULT_KEY_SIZE;
            this.PasswordIterations = DEFAULT_PASSWORD_ITERATIONS;
        }

        #endregion

        #region - Properties -

        /// <summary>
        /// Gets or sets the password.
        /// </summary>
        /// <value>
        /// The password.
        /// </value>
        public string Password
        {
            get
            {
                return _password;
            }
            set
            {
                if (string.IsNullOrEmpty(value))
                {
                    throw new ArgumentNullException("value");
                }

                _password = value;
            }
        }

        /// <summary>
        /// Gets or sets the salt.
        /// </summary>
        /// <value>
        /// The salt.
        /// </value>
        public string Salt
        {
            get
            {
                return _salt;
            }
            set
            {
                if (string.IsNullOrEmpty(value))
                {
                    throw new ArgumentNullException("value");
                }

                _salt = value;
            }
        }

        /// <summary>
        /// Gets or sets the initial vector.
        /// </summary>
        /// <value>
        /// The initial vector.
        /// </value>
        public InitialVector InitialVector
        {
            get
            {
                return _initialVector;
            }
            set
            {
                if (value == null)
                {
                    throw new ArgumentNullException("value");
                }

                if (!value.IsValid)
                {
                    throw new ArgumentException("The initial vector does not have a valid value.", "value");
                }

                _initialVector = value;
            }
        }

        /// <summary>
        /// Gets or sets the hash algorithm.
        /// </summary>
        /// <value>
        /// The hash algorithm.
        /// </value>
        public HashAlgorithm HashAlgorithm { get; set; }

        /// <summary>
        /// Gets or sets the size of the key.
        /// </summary>
        /// <value>
        /// The size of the key.
        /// </value>
        public KeySize KeySize { get; set; }

        /// <summary>
        /// Gets or sets the password iterations.
        /// </summary>
        /// <value>
        /// The password iterations.
        /// </value>
        public int PasswordIterations
        {
            get
            {
                return _passwordIterations;
            }
            set
            {
                if (value <= 0)
                {
                    throw new ArgumentOutOfRangeException("value", "Password iterations must be greater than 0.");
                }

                _passwordIterations = value;
            }
        }

        #endregion

        #region - Private Methods -

        /// <summary>
        /// Gets the password bytes.
        /// </summary>
        /// <returns></returns>
        private byte[] GetPasswordBytes()
        {
            byte[] saltBytes = Encoding.ASCII.GetBytes(Salt);

            HashAlgorithm selectedHashAlgorithm = (this.HashAlgorithm == Encryption.HashAlgorithm.None) ? DEFAULT_HASH_ALGORITHM : this.HashAlgorithm;
            string hashName = Enum.GetName(typeof(Encryption.HashAlgorithm), selectedHashAlgorithm);

            KeySize selectedKeySize = (this.KeySize == Encryption.KeySize.None) ? DEFAULT_KEY_SIZE : this.KeySize;
            int keySize = (int)selectedKeySize;

            PasswordDeriveBytes pdb = new PasswordDeriveBytes(Password, saltBytes, hashName, this.PasswordIterations);
            return pdb.GetBytes(keySize);
        }

        /// <summary>
        /// Gets the encryptor.
        /// </summary>
        /// <returns></returns>
        private ICryptoTransform GetEncryptor()
        {
            byte[] ivBytes = InitialVector.ToByteArray();
            byte[] keyBytes = GetPasswordBytes();

            return _aes.CreateEncryptor(keyBytes, ivBytes);
        }

        /// <summary>
        /// Gets the decryptor.
        /// </summary>
        /// <returns></returns>
        private ICryptoTransform GetDecryptor()
        {
            byte[] ivBytes = InitialVector.ToByteArray();
            byte[] keyBytes = GetPasswordBytes();

            return _aes.CreateDecryptor(keyBytes, ivBytes);
        }

        #endregion

        #region - Public Methods -

        /// <summary>
        /// Encrypts the specified plain text.
        /// </summary>
        /// <param name="plainText">The plain text.</param>
        /// <returns></returns>
        /// <exception cref="System.ArgumentNullException">plainText</exception>
        public string Encrypt(string plainText)
        {
            if (string.IsNullOrEmpty(plainText))
            {
                throw new ArgumentNullException("plainText");
            }

            byte[] cipherTextBytes = null;
            using (ICryptoTransform encryptor = GetEncryptor())
            {
                using (MemoryStream memStream = new MemoryStream())
                {
                    using (CryptoStream cryptoStream = new CryptoStream(memStream, encryptor, CryptoStreamMode.Write))
                    {
                        byte[] plainTextBytes = Encoding.UTF8.GetBytes(plainText);
                        cryptoStream.Write(plainTextBytes, 0, plainTextBytes.Length);
                        cryptoStream.FlushFinalBlock();
                        cipherTextBytes = memStream.ToArray();
                    }
                }
            }

            return Convert.ToBase64String(cipherTextBytes);
        }

        /// <summary>
        /// Decrypts the specified crypto text.
        /// </summary>
        /// <param name="cryptoText">The crypto text.</param>
        /// <returns></returns>
        /// <exception cref="System.ArgumentNullException">cryptoText</exception>
        public string Decrypt(string cryptoText)
        {
            if (string.IsNullOrEmpty(cryptoText))
            {
                throw new ArgumentNullException("cryptoText");
            }

            byte[] cipherTextBytes = Convert.FromBase64String(cryptoText);
            byte[] plainTextBytes = new byte[cipherTextBytes.Length];

            using (ICryptoTransform decryptor = GetDecryptor())
            {
                using (MemoryStream memStream = new MemoryStream(cipherTextBytes))
                {
                    using (CryptoStream cryptoStream = new CryptoStream(memStream, decryptor, CryptoStreamMode.Read))
                    {
                        cryptoStream.Read(plainTextBytes, 0, plainTextBytes.Length);
                    }
                }
            }

            return Encoding.UTF8.GetString(plainTextBytes, 0, plainTextBytes.Length);
        }

        #endregion

        #region - Dispose Methods -

        /// <summary>
        /// Performs application-defined tasks associated with freeing, releasing, or resetting unmanaged resources.
        /// </summary>
        public void Dispose()
        {
            Dispose(true);
        }

        /// <summary>
        /// Releases unmanaged and - optionally - managed resources.
        /// </summary>
        /// <param name="disposing"><c>true</c> to release both managed and unmanaged resources; <c>false</c> to release only unmanaged resources.</param>
        public void Dispose(bool disposing)
        {
            if (disposing)
            {
                if (_aes != null)
                {
                    _aes.Dispose();
                    _aes = null;
                }
            }
        }

        #endregion

    }
}
