import{s as t}from"./index.b48d3751.js";function r(e){return t({url:"/admin/role/list",method:"get",params:e})}function n(e){return t({url:"/admin/role/save",method:"post",params:e})}function i(e){return t({url:"/admin/role/delete/"+e,method:"post"})}function l(e,o){return t({url:"/admin/role/"+e+"/permissions/save",method:"post",data:o,headers:{"Content-Type":"application/x-www-form-urlencoded"}})}function a(e){return t({url:"/admin/role/"+e+"/permissions",method:"get"})}function d(){return t({url:"/admin/role/list/select",method:"get"})}export{a,l as b,d as c,i as d,r as g,n as s};
