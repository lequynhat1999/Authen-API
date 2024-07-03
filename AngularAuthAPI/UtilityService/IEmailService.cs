using AngularAuth.Common.Model;

namespace AngularAuth.API.UtilityService
{
    public interface IEmailService
    {
        void SendEmail(EmailModel emailModel);
    }
}
