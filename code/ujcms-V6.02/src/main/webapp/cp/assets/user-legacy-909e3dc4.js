System.register(["./index-legacy-1e63c30f.js"],(function(a,e){"use strict";var t;return{setters:[a=>{t=a.aN}],execute:function(){a("q",(async a=>(await t.get("/backend/core/org",{params:a})).data)),a("x",(async a=>(await t.get(`/backend/core/org/${a}`)).data)),a("y",(async a=>(await t.post("/backend/core/org",a)).data)),a("z",(async a=>(await t.post("/backend/core/org?_method=put",a)).data)),a("B",(async a=>(await t.post("/backend/core/org/order?_method=put",a)).data)),a("A",(async a=>(await t.post("/backend/core/org?_method=delete",a)).data)),a("h",(async a=>(await t.get("/backend/core/role",{params:a})).data)),a("l",(async a=>(await t.get(`/backend/core/role/${a}`)).data)),a("n",(async a=>(await t.post("/backend/core/role",a)).data)),a("o",(async a=>(await t.post("/backend/core/role?_method=put",a)).data)),a("s",(async a=>(await t.post("/backend/core/role/permission?_method=put",a)).data)),a("w",(async a=>(await t.post("/backend/core/role/order?_method=put",a)).data)),a("p",(async a=>(await t.post("/backend/core/role?_method=delete",a)).data)),a("t",(async(a,e)=>(await t.get("/backend/core/role/article-permissions",{params:{roleId:a,siteId:e}})).data)),a("v",(async(a,e)=>(await t.get("/backend/core/role/channel-permissions",{params:{roleId:a,siteId:e}})).data)),a("r",(async a=>(await t.get("/backend/core/role/scope-not-allowed",{params:{scope:a}})).data)),a("f",(async a=>(await t.get("/backend/core/group",{params:a})).data)),a("C",(async a=>(await t.get(`/backend/core/group/${a}`)).data)),a("D",(async a=>(await t.post("/backend/core/group",a)).data)),a("E",(async a=>(await t.post("/backend/core/group?_method=put",a)).data)),a("G",(async a=>(await t.post("/backend/core/group/permission?_method=put",a)).data)),a("I",(async a=>(await t.post("/backend/core/group/order?_method=put",a)).data)),a("F",(async a=>(await t.post("/backend/core/group?_method=delete",a)).data)),a("H",(async(a,e)=>(await t.get("/backend/core/group/access-permissions",{params:{groupId:a,siteId:e}})).data)),a("j",(async a=>(await t.get("/backend/core/user",{params:a})).data)),a("a",(async a=>(await t.get(`/backend/core/user/${a}`)).data)),a("c",(async a=>(await t.post("/backend/core/user",a)).data)),a("b",(async a=>(await t.post("/backend/core/user?_method=put",a)).data)),a("i",(async a=>(await t.post("/backend/core/user/permission?_method=put",a)).data)),a("g",(async(a,e)=>(await t.post("/backend/core/user/password?_method=put",{id:a,password:e})).data)),a("k",(async(a,e)=>(await t.post("/backend/core/user/status?_method=put",{ids:a,status:e})).data)),a("d",(async a=>(await t.post("/backend/core/user?_method=delete",a)).data)),a("u",(async a=>(await t.get("/backend/core/user/username-exist",{params:{username:a}})).data)),a("e",(async a=>(await t.get("/backend/core/user/email-exist",{params:{email:a}})).data)),a("m",(async a=>(await t.get("/backend/core/user/mobile-exist",{params:{mobile:a}})).data))}}}));
