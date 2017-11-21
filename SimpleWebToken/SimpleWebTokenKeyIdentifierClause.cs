using System;
using System.IdentityModel.Tokens;

namespace Security.SimpleWebToken
{
    public class SimpleWebTokenKeyIdentifierClause : SecurityKeyIdentifierClause
    {
        const string LocalId = "SimpleWebToken";

        private string _audience;

        public SimpleWebTokenKeyIdentifierClause(string audience)
            : base(LocalId)
        {
            if (audience == null)
            {
                throw new ArgumentNullException("audience");
            }
            _audience = audience;
        }

        public string Audience
        {
            get
            {
                return _audience;
            }
        }

        public override bool Matches(SecurityKeyIdentifierClause keyIdentifierClause)
        {
            if (keyIdentifierClause is SimpleWebTokenKeyIdentifierClause)
            {
                return true;
            }

            return false;
        }
    }
}
