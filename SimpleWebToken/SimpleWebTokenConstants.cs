namespace Security.SimpleWebToken
{
    /// <summary>
    /// Defines the set of constants for the Simple Web Token.
    /// </summary>
    public static class SimpleWebTokenConstants
    {
        public const string Audience = "Audience";
        public const string ExpiresOn = "ExpiresOn";
        public const string Id = "Id";
        public const string Issuer = "Issuer";
        public const string Signature = "HMACSHA256";
        public const string ValidFrom = "ValidFrom";
        public const string ValueTypeUri = "http://schemas.xmlsoap.org/ws/2009/11/swt-token-profile-1.0";
    }
}
