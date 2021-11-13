using System.Text.Json.Serialization;

namespace WebApi.Entities
{
    public class Document
    {
        public int Id { get; set; }
        public string Name { get; set; }
        public string Data { get; set; }
        
        [JsonIgnore]
        public int UserId { get; set; }
    }
}
