const fs = require('fs');
const path = require('path');

// 需要清理的文件和对应的未使用导入
const filesToClean = {
  'src/pages/PopularSharesPage.tsx': ['message'],
  'src/pages/RegisterPage.tsx': ['message'],
  'src/pages/Settings.tsx': ['List'],
  'src/pages/ShareHistoryPage.tsx': ['message'],
  'src/pages/NotificationPage.tsx': ['Pagination'],
  'src/pages/LoginPage.tsx': ['message']
};

function cleanUnusedImports() {
  const frontendDir = path.join(__dirname, 'frontend');
  
  Object.entries(filesToClean).forEach(([filePath, unusedImports]) => {
    const fullPath = path.join(frontendDir, filePath);
    
    if (!fs.existsSync(fullPath)) {
      console.log(`文件不存在: ${fullPath}`);
      return;
    }
    
    let content = fs.readFileSync(fullPath, 'utf8');
    let modified = false;
    
    // 移除未使用的导入
    unusedImports.forEach(importName => {
      const originalContent = content;
      
      // 处理导入在中间的情况
      const middleImportRegex = new RegExp(`(,\s*)${importName}(\s*,)`, 'g');
      content = content.replace(middleImportRegex, '$2');
      
      // 处理导入在开头的情况
      const startImportRegex = new RegExp(`(import\s*{\s*)${importName}\s*,\s*`, 'g');
      content = content.replace(startImportRegex, '$1');
      
      // 处理导入在末尾的情况
      const endImportRegex = new RegExp(`(,\s*)${importName}(\s*})`, 'g');
      content = content.replace(endImportRegex, '$2');
      
      // 处理只有一个导入的情况
      const singleImportRegex = new RegExp(`import\s*{\s*${importName}\s*}\s*from\s*['"]\[^'"]*['"]\;?\s*\n?`, 'g');
      content = content.replace(singleImportRegex, '');
      
      if (content !== originalContent) {
        modified = true;
      }
    });
    
    if (modified) {
      // 清理多余的逗号和空格
       content = content.replace(/import\s*{\s*,/g, 'import {');
       content = content.replace(/,\s*}/g, ' }');
       content = content.replace(/\{\s*,/g, '{');
       content = content.replace(/,\s*,/g, ',');
       content = content.replace(/\{\s*}/g, '{}');
      
      fs.writeFileSync(fullPath, content, 'utf8');
      console.log(`已清理 ${filePath} 中的未使用导入: ${unusedImports.join(', ')}`);
    } else {
      console.log(`${filePath} 中未找到需要清理的导入: ${unusedImports.join(', ')}`);
    }
  });
}

cleanUnusedImports();
console.log('未使用导入清理完成！');