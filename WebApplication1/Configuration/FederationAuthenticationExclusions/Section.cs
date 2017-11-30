using System.Configuration;

namespace WebApplication1.Configuration.FederationAuthenticationExclusions
{
    public class Section : ConfigurationSection
    {
        private static Section _instance = (Section)ConfigurationManager.GetSection("federationAuthenticationExclusions") ?? new Section();

        public static Section Default
        {
            get { return _instance; }
        }

        [ConfigurationProperty("items")]
        public Items Items
        {
            get
            {
                return (Items)(base["items"]);
            }
        }
    }
}