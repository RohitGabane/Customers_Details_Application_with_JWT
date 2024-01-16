using System.ComponentModel.DataAnnotations;

namespace UI.Models
{
    public class CommunicationHistory
    {
        [Key]
        public int CommunicationId { get; set; }
        public int CustomerId { get; set; }
        public DateTime CommunicationDate { get; set; }
        public string CommunicationType { get; set; }
        public string CommunicationDetails { get; set; }
    }
}
