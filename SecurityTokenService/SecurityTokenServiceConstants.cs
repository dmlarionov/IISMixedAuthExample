namespace SecurityTokenService
{
    public static class SecurityTokenServiceConstants
    {
        public static class WSFederation
        {
            public static class Parameters
            {
                public const string Action = "wa";
                public const string WReply = "wreply";
                public const string WTRealm = "wtrealm";
                public const string Wct = "wct";
            }

            public static class Actions
            {
                public const string SignIn = "wsignin1.0";
                public const string SignOut = "wsignout1.0";
            }
        }
    }
}