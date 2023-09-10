import{d as te,u as oe,r as i,X as V,v as se,o as ne,a as d,b as ie,c as v,e as y,w as o,h as l,I as de,a8 as ce,a7 as me,j as S,i as s,as as p,a5 as re,k as $,t as C,a2 as ue,f as pe,g as q,aD as be,aJ as _e,E as z,aL as ve,_ as fe}from"./index-285670b0.js";import{a as ke}from"./config-43502fd6.js";import{D as ge,E as ye,t as Ie,F as he}from"./content-214478a8.js";import{_ as we,a as Be,b as Ve,c as $e}from"./QueryItem.vue_vue_type_script_setup_true_lang-c40055fe.js";import{_ as Ce}from"./ListMove.vue_vue_type_script_setup_true_lang-591ffc50.js";import{a as Le}from"./BlockItemForm.vue_vue_type_script_setup_true_lang-7306d3b0.js";import"./DialogForm.vue_vue_type_script_setup_true_lang-2cec4ef8.js";import"./FileListUpload.vue_vue_type_style_index_0_scoped_cd89d899_lang-908ae973.js";import"./BaseUpload-8033ede3.js";/* empty css                                                                   */const De={class:"mb-3"},Se={class:"app-block mt-3"},Ne={name:"BlockItemList"},Ue=te({...Ne,setup(Ee){const{t:N}=oe(),I=i({}),f=i(),U=i(),b=i([]),k=i([]),L=i(!1),h=i(!1),D=i(),Q=V(()=>b.value.map(e=>e.id)),E=i(!1),w=i([]),r=i(),A=V(()=>w.value.find(e=>e.id===Number(r.value))),J=V(()=>b.value.map(e=>e.image)),T=V(()=>b.value.map(e=>e.mobileImage)),u=async()=>{L.value=!0;try{b.value=await ge({...be(I.value),blockId:Number(r.value),Q_OrderBy:f.value}),E.value=Object.values(I.value).filter(e=>e!==void 0&&e!=="").length>0||f.value!==void 0}finally{L.value=!1}},X=async()=>{w.value=await ke(),r.value=String(w.value[0].id)};se(r,()=>u()),ne(async()=>{await X()});const G=({column:e,prop:t,order:g})=>{var _;t?f.value=((_=e.sortBy)!=null?_:t)+(g==="descending"?"_desc":""):f.value=void 0,u()},H=()=>u(),K=()=>{U.value.clearSort(),_e(I.value),f.value=void 0,u()},W=()=>{D.value=void 0,h.value=!0},F=e=>{D.value=e,h.value=!0},M=async e=>{await ye(e),u(),z.success(N("success"))},O=async e=>{await Ie(e),u(),z.success(N("success"))},Y=async(e,t)=>{const g=ve(e,b.value,t);await he(g.map(_=>_.id))};return(e,t)=>{const g=d("el-tab-pane"),_=d("el-tabs"),Z=d("el-aside"),B=d("el-button"),P=d("el-popconfirm"),c=d("el-table-column"),R=d("el-image"),j=d("el-switch"),x=d("el-table"),ee=d("el-main"),ae=d("el-container"),le=ie("loading");return v(),y(ae,null,{default:o(()=>[l(Z,{width:"180px",class:"pr-3"},{default:o(()=>[l(_,{modelValue:r.value,"onUpdate:modelValue":t[0]||(t[0]=m=>r.value=m),"tab-position":"left",stretch:"",class:"bg-white"},{default:o(()=>[(v(!0),de(me,null,ce(w.value,m=>(v(),y(g,{key:m.id,name:String(m.id),label:m.name},null,8,["name","label"]))),128))]),_:1},8,["modelValue"])]),_:1}),l(ee,{class:"p-0"},{default:o(()=>{var m;return[S("div",De,[l(s(we),{params:I.value,onSearch:H,onReset:K},{default:o(()=>[l(s(Be),{label:e.$t("blockItem.title"),name:"Q_Contains_title"},null,8,["label"])]),_:1},8,["params"])]),S("div",null,[l(B,{type:"primary",disabled:!((m=s(A))!=null&&m.enabled)||s(p)("blockItem:create"),icon:s(re),onClick:t[1]||(t[1]=()=>W())},{default:o(()=>[$(C(e.$t("add")),1)]),_:1},8,["disabled","icon"]),l(P,{title:e.$t("confirmDelete"),onConfirm:t[2]||(t[2]=()=>O(k.value.map(a=>a.id)))},{reference:o(()=>[l(B,{disabled:k.value.length<=0||s(p)("blockItem:delete"),icon:s(ue)},{default:o(()=>[$(C(e.$t("delete")),1)]),_:1},8,["disabled","icon"])]),_:1},8,["title"]),l(Ce,{disabled:k.value.length<=0||E.value||s(p)("org:update"),class:"ml-2",onMove:t[3]||(t[3]=a=>Y(k.value,a))},null,8,["disabled"]),l(s(Ve),{name:"blockItem",class:"ml-2"})]),S("div",Se,[pe((v(),y(x,{ref_key:"table",ref:U,data:b.value,onSelectionChange:t[4]||(t[4]=a=>k.value=a),onRowDblclick:t[5]||(t[5]=a=>F(a.id)),onSortChange:G},{default:o(()=>[l(s($e),{name:"blockItem"},{default:o(()=>[l(c,{type:"selection",width:"45"}),l(c,{property:"id",label:"ID",width:"64",sortable:"custom"}),l(c,{property:"title",label:e.$t("blockItem.title"),sortable:"custom","min-width":"200","show-overflow-tooltip":""},null,8,["label"]),l(c,{property:"image",label:e.$t("blockItem.image")},{default:o(({row:a,$index:n})=>[a.image?(v(),y(R,{key:0,src:a.image,fit:"contain","preview-src-list":s(J),"initial-index":n,"preview-teleported":"",class:"w-32 h-32"},null,8,["src","preview-src-list","initial-index"])):q("",!0)]),_:1},8,["label"]),l(c,{property:"mobileImage",label:e.$t("blockItem.mobileImage"),display:"none"},{default:o(({row:a,$index:n})=>[a.mobileImage?(v(),y(R,{key:0,src:a.mobileImage,fit:"contain","preview-src-list":s(T),"initial-index":n,"preview-teleported":"",class:"w-32 h-32"},null,8,["src","preview-src-list","initial-index"])):q("",!0)]),_:1},8,["label"]),l(c,{property:"targetBlank",label:e.$t("blockItem.targetBlank"),sortable:"custom",width:"120"},{default:o(({row:a})=>[l(j,{modelValue:a.targetBlank,"onUpdate:modelValue":n=>a.targetBlank=n,disabled:s(p)("blockItem:update"),onChange:n=>M({...a,targetBlank:n})},null,8,["modelValue","onUpdate:modelValue","disabled","onChange"])]),_:1},8,["label"]),l(c,{property:"enabled",label:e.$t("enable"),sortable:"custom",width:"100"},{default:o(({row:a})=>[l(j,{modelValue:a.enabled,"onUpdate:modelValue":n=>a.enabled=n,disabled:s(p)("blockItem:update"),onChange:n=>M({...a,enabled:n})},null,8,["modelValue","onUpdate:modelValue","disabled","onChange"])]),_:1},8,["label"]),l(c,{label:e.$t("table.action")},{default:o(({row:a})=>[l(B,{type:"primary",disabled:s(p)("blockItem:update"),size:"small",link:"",onClick:()=>F(a.id)},{default:o(()=>[$(C(e.$t("edit")),1)]),_:2},1032,["disabled","onClick"]),l(P,{title:e.$t("confirmDelete"),onConfirm:()=>O([a.id])},{reference:o(()=>[l(B,{type:"primary",disabled:s(p)("blockItem:delete"),size:"small",link:""},{default:o(()=>[$(C(e.$t("delete")),1)]),_:1},8,["disabled"])]),_:2},1032,["title","onConfirm"])]),_:1},8,["label"])]),_:1})]),_:1},8,["data"])),[[le,L.value]])]),l(Le,{modelValue:h.value,"onUpdate:modelValue":t[6]||(t[6]=a=>h.value=a),"bean-id":D.value,"bean-ids":s(Q),"block-id":Number(r.value),onFinished:u},null,8,["modelValue","bean-id","bean-ids","block-id"])]}),_:1})]),_:1})}}});const Je=fe(Ue,[["__scopeId","data-v-36d893a7"]]);export{Je as default};
