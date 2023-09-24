## 0x00 Q&A

### 这是什么

此项目用于收集Github上一些CNNVD爆出过漏洞的CMS，来学习Java代码审计和完善Semgrep规则

### 项目结构

```
.
|-- check-rules (semgrep规则)
|   |-- my-rules (自己编写的补充规则)
|   `-- official-rules （semgrep官方规则）
|-- code （存在漏洞的源码）
|   |-- fastcms
|   `-- ujcms
`-- writeup （题解或者记录?随便吧）
```

### 如何使用此项目学习

1. 从Github上Clone此项目，注意因为有子项目，你需要使用以下的命令

   ```bash
   git clone --recursive https://github.com/chenlvtang/CodeReview-Java.git
   ```

2. 切换到需要审计的源码目录

   ```bash
   cd CodeReview/code/fastcms
   ```

3. 使用git checkout切换到漏洞版本 (可以在下文或者git log、writeup对应md文件查看节点)

   ```bash
   git log
   git checkout 43f2b8498a842a232dad8b0aebc7c18e2f23ac1c
   ```

4. 使用semgrep或者其他SAST工具进行审计

   ```bash
   cd ../../
   semgrep -c check-rules/official-rules/java -c check-rules/my-rules code/fastcms -o res/fastcms.json --json
   ```

5. 查看Writeup，看看自己是不是找到了对应的漏洞（或者恭喜你，发现了其他人没发现的漏洞）

6. 切换到修复版本，比较差异，学习漏洞代码和修复方法，并完善semgrep规则（如果现有规则没检查出）

6. 为此项目添砖加瓦

### 每个项目的漏洞全吗

不全，能力有限，如果你可以挖到别人没挖到的，快去提交吧

### 每个项目已知的漏洞有哪些

格式：漏洞编号，粗略的漏洞信息，漏洞git节点 

#### FastCMS

+ CNNVD-202303-341，Zip Slip目录穿越，43f2b8498a842a232dad8b0aebc7c18e2f23ac1c
+ CNNVD-202302-160，任意文件上传，6f12004ca9b918d6384dbc5919310b7577c1daaa [比对完git记录都没看到哪里改动了，但是确实有一个文件上传，最新版也有，已通知作者修复]
+ CNNVD-202212-2537，Freemarker模板注入，[压根没修，任意版本即可]

### 我想参与

欢迎🎉，Fork之后，提交Pull Request即可（如果还包含semgrep的rules，请移步[另一个项目](https://github.com/chenlvtang/MySemgrepRules)提交）

## 0x02 更新/计划

### 更新记录

+ 2023.09.19：上一周发烧了，所以没更新，哈哈

+ 2023.09.10：开始&更新FastCMS

### 计划

~~没有计划，随缘更新~~

- [ ] 每周一更，哈哈，就是这么摆烂
