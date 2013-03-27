#region - Using Statements -

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

#endregion

namespace Encryption
{
    /// <summary>
    /// An enumeration of hash algorithms used to generate a key for the encryption algorithm.
    /// </summary>
    public enum HashAlgorithm
    {
        /// <summary>
        /// No hash algorithm selected.
        /// </summary>
        None,
        /// <summary>
        /// The SHA-1 hash algorithm.
        /// </summary>
        SHA1,
        /// <summary>
        /// The MD5 hash algorithm.
        /// </summary>
        MD5
    }
}
