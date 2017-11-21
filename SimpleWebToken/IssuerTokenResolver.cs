using System.Collections.Generic;
using System.IdentityModel.Tokens;
using System.IO;
using System.Text;
using System.Xml;

namespace Security.SimpleWebToken
{
    public class IssuerTokenResolver : System.IdentityModel.Tokens.IssuerTokenResolver
    {
        private Dictionary<string, string> _keys;

        public IssuerTokenResolver()
        {
            _keys = new Dictionary<string, string>();
        }

        public void AddAudienceKeyPair(string audience, string symmetricKey)
        {
            _keys.Add(audience, symmetricKey);
        }

        public override void LoadCustomConfiguration(XmlNodeList nodelist)
        {
            foreach (XmlNode node in nodelist)
            {
                var rdr = XmlDictionaryReader.CreateDictionaryReader(new XmlTextReader(new StringReader(node.OuterXml)));
                rdr.MoveToContent();

                var symmetricKey = rdr.GetAttribute("symmetricKey");
                var audience = rdr.GetAttribute("audience");

                AddAudienceKeyPair(audience, symmetricKey);
            }
        }

        protected override bool TryResolveSecurityKeyCore(SecurityKeyIdentifierClause keyIdentifierClause, out SecurityKey key)
        {
            key = null;
            var keyClause = keyIdentifierClause as SimpleWebTokenKeyIdentifierClause;
            if (keyClause != null)
            {
                string base64Key = null;
                _keys.TryGetValue(keyClause.Audience, out base64Key);
                if (!string.IsNullOrEmpty(base64Key))
                {
                    key = new InMemorySymmetricSecurityKey(Encoding.UTF8.GetBytes(base64Key));
                    return true;
                }
            }

            return false;
        }

    }
}
