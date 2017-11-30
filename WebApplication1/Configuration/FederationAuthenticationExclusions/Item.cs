using System.Configuration;

namespace WebApplication1.Configuration.FederationAuthenticationExclusions
{
    public class Item : ConfigurationElement
    {
        [ConfigurationProperty("url", IsKey = true, IsRequired = true)]
        public string Url
        {
            get
            {
                return (string)base["url"];
            }

            set
            {
                base["url"] = value;
            }
        }
    }
}