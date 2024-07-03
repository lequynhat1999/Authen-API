using AngularAuth.BL.Interface;
using AngularAuth.Common.Model;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AngularAuth.BL
{
    public class UserBL : IUserBL
    {
        public UserBL() { }
        public async Task<ServiceResponse> Login(User user)
        {
            var res = new ServiceResponse();
            if(user == null)
            {
                res.Success = false;
                return res;
            }


            return res;
        }

        public async Task<ServiceResponse> Register(User user)
        {
            var res = new ServiceResponse();
            if (user == null)
            {
                res.Success = false;
                return res;
            }
            
            



            return res;
        }
    }
}
