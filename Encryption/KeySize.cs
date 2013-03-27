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
    /// Enumeration of key sizes available for the encryption algorithm.
    /// </summary>
    public enum KeySize
    {
        /// <summary>
        /// No key size selected.
        /// </summary>
        None = 0,
        /// <summary>
        /// A key size of 128 bits.
        /// </summary>
        KeySize128 = 16,
        /// <summary>
        /// A key size of 192 bits.
        /// </summary>
        KeySize192 = 24,
        /// <summary>
        /// A key size of 256 bits.
        /// </summary>
        KeySize256 = 32
    }
}
