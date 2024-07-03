using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AngularAuth.Common.Model
{
    public class ServiceResponse
    {
        public bool Success { get; set; } = true;
        public string Message { get; set; } = "";
        public int ErrorCode { get; set; }
        public object Data { get; set; }
    }
}
