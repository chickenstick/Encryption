#region - Using Statements -

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

#endregion

namespace Encryption
{
    /// <summary>
    /// Represents an initial vector used in the encryption algorithm.
    /// </summary>
    public sealed class InitialVector : IEquatable<InitialVector>
    {

        #region - Static Readonly Fields -

        private static readonly Regex IV_REGEX = new Regex(@"^.{16}$", RegexOptions.Compiled | RegexOptions.Singleline);

        #endregion

        #region - Constructor -

        /// <summary>
        /// Initializes a new instance of the <see cref="InitialVector"/> class.
        /// </summary>
        /// <param name="value">The value.</param>
        public InitialVector(string value)
        {
            this.Value = value;
            this.IsValid = IsValidInitialVector(value);
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="InitialVector"/> class.
        /// </summary>
        /// <param name="value">The value.</param>
        public InitialVector(char[] value)
        {
            this.Value = new String(value);
            this.IsValid = IsValidInitialVector(this.Value);
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="InitialVector"/> class.
        /// </summary>
        /// <param name="values">The values.</param>
        public InitialVector(byte[] values)
        {
            char[] chars = Encoding.ASCII.GetChars(values);
            this.Value = new String(chars);
            this.IsValid = IsValidInitialVector(this.Value);
        }

        #endregion

        #region - Properties -

        /// <summary>
        /// Gets the value of the initial vector.
        /// </summary>
        /// <value>
        /// The value.
        /// </value>
        public string Value { get; private set; }

        /// <summary>
        /// Gets a value indicating whether this instance is valid.
        /// </summary>
        /// <value>
        ///   <c>true</c> if this instance is valid; otherwise, <c>false</c>.
        /// </value>
        public bool IsValid { get; private set; }

        #endregion

        #region - Private Methods -

        /// <summary>
        /// Determines whether the initial vector is valid.
        /// </summary>
        /// <param name="iv">The iv.</param>
        /// <returns>
        ///   <c>true</c> if the initial vector is valid; otherwise, <c>false</c>.
        /// </returns>
        private bool IsValidInitialVector(string iv)
        {
            return IV_REGEX.IsMatch(iv);
        }

        #endregion

        #region - Public Methods -

        /// <summary>
        /// Determines whether the specified <see cref="System.Object" /> is equal to this instance.
        /// </summary>
        /// <param name="obj">The <see cref="System.Object" /> to compare with this instance.</param>
        /// <returns>
        ///   <c>true</c> if the specified <see cref="System.Object" /> is equal to this instance; otherwise, <c>false</c>.
        /// </returns>
        public override bool Equals(object obj)
        {
            InitialVector iv = obj as InitialVector;
            if (iv != null)
            {
                return this.Equals(iv);
            }

            return false;
        }

        /// <summary>
        /// Returns a hash code for this instance.
        /// </summary>
        /// <returns>
        /// A hash code for this instance, suitable for use in hashing algorithms and data structures like a hash table. 
        /// </returns>
        public override int GetHashCode()
        {
            return Value.GetHashCode();
        }

        /// <summary>
        /// Returns a <see cref="System.String" /> that represents this instance.
        /// </summary>
        /// <returns>
        /// A <see cref="System.String" /> that represents this instance.
        /// </returns>
        public override string ToString()
        {
            return Value;
        }

        /// <summary>
        /// Converts the instance to a <see cref="System.Byte"/> array.
        /// </summary>
        /// <returns></returns>
        public byte[] ToByteArray()
        {
            return Encoding.ASCII.GetBytes(this.Value);
        }

        #endregion

        #region - IEquatable<InitialVector> Members -

        /// <summary>
        /// Indicates whether the current object is equal to another object of the same type.
        /// </summary>
        /// <param name="other">An object to compare with this object.</param>
        /// <returns>
        /// true if the current object is equal to the other parameter; otherwise, false.
        /// </returns>
        public bool Equals(InitialVector other)
        {
            return this.Value.Equals(other.Value);
        }

        #endregion

        #region - Static Methods -

        /// <summary>
        /// Creates a random <see cref="Encryption.InitialVector"/>.
        /// </summary>
        /// <returns></returns>
        public static InitialVector CreateRandom()
        {
            byte[] randArray = new byte[16];
            Random random = new Random();
            random.NextBytes(randArray);
            return new InitialVector(randArray);
        }

        #endregion

    }
}
