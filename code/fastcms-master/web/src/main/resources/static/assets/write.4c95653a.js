var R=Object.defineProperty;var w=Object.getOwnPropertySymbols;var j=Object.prototype.hasOwnProperty,x=Object.prototype.propertyIsEnumerable;var k=(l,o,n)=>o in l?R(l,o,{enumerable:!0,configurable:!0,writable:!0,value:n}):l[o]=n,v=(l,o)=>{for(var n in o||(o={}))j.call(o,n)&&k(l,n,o[n]);if(w)for(var n of w(o))x.call(o,n)&&k(l,n,o[n]);return l};import{r as y,M as H,j as O,o as L,t as q,l as s,m as S,z as e,A as t,b as T,D as B,Y as K,X as N,Q as I,G as z,x as C}from"./vendor.07d41a1e.js";import{A as M}from"./index.cae9994f.js";import{b as G,c as P,e as Q,f as W}from"./client.f4e5d85b.js";import{l as X}from"./index.34a00848.js";import{C as Y}from"./index.1a97bf2c.js";import{_ as J}from"./index.b48d3751.js";import"./index.30cc523d.js";import"./client.5fb9dd1e.js";const Z={name:"clientArticleWrite",components:{AttachDialog:M,ckeditor:Y},setup(l,o){const n=y(),i=y(),V=y(),D=H(),{proxy:d}=z(),u=O({fit:"fill",row:null,isShowDialog:!1,params:{},categories:[],tags:[],ruleForm:{title:"",commentEnable:1,contentHtml:"",summary:"",seoKeywords:"",seoDescription:"",outLink:"",sortNum:0,thumbnail:"",suffix:""},rules:{title:{required:!0,message:"\u8BF7\u8F93\u5165\u6587\u7AE0\u6807\u9898",trigger:"blur"},contentHtml:{required:!0,message:"\u8BF7\u8F93\u5165\u6587\u7AE0\u8BE6\u60C5",trigger:"blur"},thumbnail:{required:!0,message:"\u8BF7\u9009\u62E9\u7F29\u7565\u56FE",trigger:"blur"},summary:{required:!0,message:"\u8BF7\u8F93\u5165\u6587\u7AE0\u6458\u8981",trigger:"blur"},seoKeywords:{required:!0,message:"\u8BF7\u8F93\u5165SEO\u5173\u952E\u8BCD",trigger:"blur"},seoDescription:{required:!0,message:"\u8BF7\u8F93\u5165SEO\u63CF\u8FF0",trigger:"blur"}}}),m=()=>{G().then(r=>{u.categories=r.data}),P().then(r=>{r.data.forEach(c=>{u.tags.push(c)})})},F=()=>{d.$refs.myRefForm.validate(r=>{if(r){let c=X.stringify(u.ruleForm,{arrayFormat:"repeat"});Q(c).then(p=>{u.ruleForm.id=p.data,T.success("\u4FDD\u5B58\u6210\u529F")}).catch(p=>{T({showClose:!0,message:p.message?p.message:"\u7CFB\u7EDF\u9519\u8BEF",type:"error"})})}})},f=r=>{W(r).then(c=>{u.ruleForm=c.data})},g=r=>{console.log(r)},b=()=>{n.value.openDialog(1)},_=()=>{i.value.openDialog(1)},h=r=>{u.ruleForm.thumbnail=r[0].filePath,u.ruleForm.thumbnailUrl=r[0].path},E=r=>{u.ruleForm.attachId=r[0].id,u.ruleForm.attachTitle=r[0].fileName};return L(()=>{u.params=D,m();let r=u.params.query.id;r&&f(r)}),v({thumbnailDialogRef:n,attachDialogRef:i,categoryCascaderRef:V,onSubmit:F,onThumbnailDialogOpen:b,onAttachlDialogOpen:_,getSelectThumbnail:h,getSelectAttach:E,getCategoryList:m,getArticleInfo:f,onEditorReady:g},q(u))}},$={class:"container"},ee=C("\u9009\u62E9\u56FE\u7247"),le=C("\u9009\u62E9\u9644\u4EF6"),te=C("\u4FDD \u5B58");function oe(l,o,n,i,V,D){const d=s("el-input"),u=s("el-form-item"),m=s("el-col"),F=s("ckeditor"),f=s("el-image"),g=s("el-link"),b=s("el-switch"),_=s("el-cascader"),h=s("el-option"),E=s("el-select"),r=s("el-row"),c=s("el-button"),p=s("el-form"),U=s("el-card"),A=s("AttachDialog");return B(),S("div",$,[e(U,null,{default:t(()=>[e(p,{model:l.ruleForm,size:"small","label-width":"100px",rules:l.rules,ref:"myRefForm"},{default:t(()=>[e(r,{gutter:35},{default:t(()=>[e(m,{class:"mb20"},{default:t(()=>[e(u,{label:"\u6807\u9898",prop:"title"},{default:t(()=>[e(d,{modelValue:l.ruleForm.title,"onUpdate:modelValue":o[0]||(o[0]=a=>l.ruleForm.title=a),placeholder:"\u8BF7\u8F93\u5165\u6587\u7AE0\u6807\u9898",clearable:""},null,8,["modelValue"])]),_:1})]),_:1}),e(m,{class:"mb20"},{default:t(()=>[e(u,{label:"\u6587\u7AE0\u8BE6\u60C5",prop:"contentHtml"},{default:t(()=>[e(F,{modelValue:l.ruleForm.contentHtml,"onUpdate:modelValue":o[1]||(o[1]=a=>l.ruleForm.contentHtml=a),isClient:!0},null,8,["modelValue"])]),_:1})]),_:1}),e(m,{class:"mb20"},{default:t(()=>[e(u,{label:"\u7F29\u7565\u56FE",prop:"thumbnail"},{default:t(()=>[e(f,{style:{width:"100px",height:"100px"},src:l.ruleForm.thumbnailUrl,fit:l.fit},null,8,["src","fit"])]),_:1}),e(u,null,{default:t(()=>[e(g,{type:"primary",onClick:i.onThumbnailDialogOpen},{default:t(()=>[ee]),_:1},8,["onClick"])]),_:1})]),_:1}),e(m,{class:"mb20"},{default:t(()=>[e(u,{label:"\u6587\u7AE0\u6458\u8981",prop:"summary"},{default:t(()=>[e(d,{modelValue:l.ruleForm.summary,"onUpdate:modelValue":o[2]||(o[2]=a=>l.ruleForm.summary=a),type:"textarea",rows:2,placeholder:"\u8BF7\u8F93\u5165\u6587\u7AE0\u6458\u8981",clearable:""},null,8,["modelValue"])]),_:1})]),_:1}),e(m,{xs:24,sm:12,md:12,lg:12,xl:12,class:"mb20"},{default:t(()=>[e(u,{label:"SEO\u5173\u952E\u8BCD",prop:"seoKeywords"},{default:t(()=>[e(d,{type:"textarea",rows:2,modelValue:l.ruleForm.seoKeywords,"onUpdate:modelValue":o[3]||(o[3]=a=>l.ruleForm.seoKeywords=a),placeholder:"\u8BF7\u8F93\u5165seo\u5173\u952E\u8BCD",clearable:""},null,8,["modelValue"])]),_:1})]),_:1}),e(m,{xs:24,sm:12,md:12,lg:12,xl:12,class:"mb20"},{default:t(()=>[e(u,{label:"SEO\u63CF\u8FF0",prop:"seoDescription"},{default:t(()=>[e(d,{type:"textarea",rows:2,modelValue:l.ruleForm.seoDescription,"onUpdate:modelValue":o[4]||(o[4]=a=>l.ruleForm.seoDescription=a),placeholder:"\u8BF7\u8F93\u5165SEO\u63CF\u8FF0",clearable:""},null,8,["modelValue"])]),_:1})]),_:1}),e(m,{xs:24,sm:12,md:12,lg:12,xl:12,class:"mb20"},{default:t(()=>[e(u,{label:"\u5916\u94FE",prop:"outLink"},{default:t(()=>[e(d,{modelValue:l.ruleForm.outLink,"onUpdate:modelValue":o[5]||(o[5]=a=>l.ruleForm.outLink=a),placeholder:"\u8BF7\u8F93\u5165\u5916\u94FE",clearable:""},null,8,["modelValue"])]),_:1})]),_:1}),e(m,{xs:24,sm:12,md:12,lg:12,xl:12,class:"mb20"},{default:t(()=>[e(u,{label:"\u5141\u8BB8\u8BC4\u8BBA",prop:"commentEnable"},{default:t(()=>[e(b,{modelValue:l.ruleForm.commentEnable,"onUpdate:modelValue":o[6]||(o[6]=a=>l.ruleForm.commentEnable=a),"active-color":"#13ce66"},null,8,["modelValue"])]),_:1})]),_:1}),e(m,{xs:24,sm:12,md:12,lg:12,xl:12,class:"mb20"},{default:t(()=>[e(u,{label:"\u5206\u7C7B",prop:"categories"},{default:t(()=>[e(_,{ref:"categoryCascader",modelValue:l.ruleForm.articleCategory,"onUpdate:modelValue":o[7]||(o[7]=a=>l.ruleForm.articleCategory=a),options:l.categories,props:{multiple:!0,label:"label",value:"id",children:"children"},"collapse-tags":"",clearable:""},null,8,["modelValue","options"])]),_:1})]),_:1}),e(m,{xs:24,sm:12,md:12,lg:12,xl:12,class:"mb20"},{default:t(()=>[e(u,{label:"\u6807\u7B7E",prop:"tags"},{default:t(()=>[e(E,{modelValue:l.ruleForm.articleTag,"onUpdate:modelValue":o[8]||(o[8]=a=>l.ruleForm.articleTag=a),class:"w100",multiple:"",filterable:"","default-first-option":"",placeholder:"\u8BF7\u9009\u62E9\u6807\u7B7E"},{default:t(()=>[(B(!0),S(K,null,N(l.tags,a=>(B(),I(h,{key:a.id,label:a.tagName,value:a.tagName},null,8,["label","value"]))),128))]),_:1},8,["modelValue"])]),_:1})]),_:1}),e(m,{xs:24,sm:24,md:24,lg:24,xl:24,class:"mb20"},{default:t(()=>[e(u,{label:"\u9644\u4EF6",prop:"attachTitle"},{default:t(()=>[e(d,{modelValue:l.ruleForm.attachTitle,"onUpdate:modelValue":o[9]||(o[9]=a=>l.ruleForm.attachTitle=a),readonly:""},null,8,["modelValue"])]),_:1}),e(u,null,{default:t(()=>[e(g,{type:"primary",onClick:i.onAttachlDialogOpen},{default:t(()=>[le]),_:1},8,["onClick"])]),_:1})]),_:1})]),_:1}),e(r,null,{default:t(()=>[e(u,null,{default:t(()=>[e(c,{type:"primary",onClick:i.onSubmit,size:"small"},{default:t(()=>[te]),_:1},8,["onClick"])]),_:1})]),_:1})]),_:1},8,["model","rules"])]),_:1}),e(A,{ref:"thumbnailDialogRef",onAttachHandler:i.getSelectThumbnail,isClient:!0},null,8,["onAttachHandler"]),e(A,{ref:"attachDialogRef",onAttachHandler:i.getSelectAttach,isClient:!0},null,8,["onAttachHandler"])])}var pe=J(Z,[["render",oe]]);export{pe as default};
