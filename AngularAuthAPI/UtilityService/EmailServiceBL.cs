using AngularAuth.Common.Model;
using MailKit.Net.Smtp;
using MimeKit;

namespace AngularAuth.API.UtilityService
{
    public class EmailServiceBL : IEmailService
    {
        private readonly IConfiguration _config;
        public EmailServiceBL(IConfiguration configuration) 
        {
            _config = configuration;
        }
        public void SendEmail(EmailModel emailModel)
        {
            var emailMessage = new MimeMessage();
            var from = _config["EmailConfig:From"];
            emailMessage.From.Add(new MailboxAddress("Le Quy Nhat", from));
            emailMessage.To.Add(new MailboxAddress(emailModel.To, emailModel.To));
            emailMessage.Subject = emailModel.Subject;
            emailMessage.Body = new TextPart(MimeKit.Text.TextFormat.Html)
            {
                Text = string.Format(emailModel.Content)
            };

            using (var client = new SmtpClient())
            {
                try
                {
                    client.Connect(_config["EmailConfig:SmtpServer"], 465, true);
                    client.Authenticate(_config["EmailConfig:From"], _config["EmailConfig:Password"]);
                    client.Send(emailMessage);
                }
                catch (Exception ex)
                {
                    throw;
                }
                finally
                {
                    client.Disconnect(true);
                    client.Dispose();
                }
            }
        }
    }
}
