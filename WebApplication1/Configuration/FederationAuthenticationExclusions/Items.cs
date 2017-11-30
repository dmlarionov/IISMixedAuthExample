using System.Configuration;

namespace WebApplication1.Configuration.FederationAuthenticationExclusions
{
    [ConfigurationCollection(typeof(Item))]
    public class Items : ConfigurationElementCollection
    {
        protected override ConfigurationElement CreateNewElement()
        {
            return new Item();
        }

        protected override object GetElementKey(ConfigurationElement element)
        {
            return ((Item)element).Url;
        }

        public Item this[int idx]
        {
            get
            {
                return (Item)BaseGet(idx);
            }
        }

        public new Item this[string url]
        {
            get
            {
                return (Item)BaseGet(url);
            }
        }
    }
}