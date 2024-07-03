using AngularAuth.Common.Model;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AngularAuth.BL.Interface
{
    public interface IUserBL
    {
        Task<ServiceResponse> Login(User user);

        Task<ServiceResponse> Register(User user);
    }
}
