const fs = require('fs');
const path = require('path');

// 检查文件中是否使用了Typography的解构
function needsTypography(content) {
  return /const\s*{[^}]*(?:Title|Text|Paragraph)[^}]*}\s*=\s*Typography/.test(content);
}

// 检查文件中是否使用了Input的解构
function needsInput(content) {
  return /const\s*{[^}]*(?:Search|Password|TextArea)[^}]*}\s*=\s*Input/.test(content);
}

// 检查文件中是否使用了message
function needsMessage(content) {
  return /message\.(success|error|warning|info|loading)/.test(content);
}

// 修复特定文件的导入问题
function fixSpecificImports(content, filePath) {
  let modified = false;
  let newContent = content;
  
  // 处理 Typography
  if (needsTypography(newContent)) {
    const antdImportRegex = /import\s*{([^}]*)}\s*from\s*['"]antd['"]/;
    const match = newContent.match(antdImportRegex);
    
    if (match && !match[1].includes('Typography')) {
      const components = match[1].split(',').map(c => c.trim()).filter(c => c.length > 0);
      components.push('Typography');
      const newImport = `import { ${components.sort().join(', ')} } from 'antd';`;
      newContent = newContent.replace(match[0], newImport);
      modified = true;
      console.log(`${filePath}: 添加 Typography 导入`);
    }
  }
  
  // 处理 Input
  if (needsInput(newContent)) {
    const antdImportRegex = /import\s*{([^}]*)}\s*from\s*['"]antd['"]/;
    const match = newContent.match(antdImportRegex);
    
    if (match && !match[1].includes('Input')) {
      const components = match[1].split(',').map(c => c.trim()).filter(c => c.length > 0);
      components.push('Input');
      const newImport = `import { ${components.sort().join(', ')} } from 'antd';`;
      newContent = newContent.replace(match[0], newImport);
      modified = true;
      console.log(`${filePath}: 添加 Input 导入`);
    }
  }
  
  // 处理 message
  if (needsMessage(newContent)) {
    const antdImportRegex = /import\s*{([^}]*)}\s*from\s*['"]antd['"]/;
    const match = newContent.match(antdImportRegex);
    
    if (match && !match[1].includes('message')) {
      const components = match[1].split(',').map(c => c.trim()).filter(c => c.length > 0);
      components.push('message');
      const newImport = `import { ${components.sort().join(', ')} } from 'antd';`;
      newContent = newContent.replace(match[0], newImport);
      modified = true;
      console.log(`${filePath}: 添加 message 导入`);
    }
  }
  
  // 移除完全未使用的导入
  const filesToClean = [
    'src/store/slices/uiSlice.ts',
    'src/utils/imageOptimization.ts',
    'src/utils/performance.ts',
    'src/pages/Settings.tsx'
  ];
  
  const relativePath = path.relative(path.join(__dirname, '..'), filePath).replace(/\\/g, '/');
  
  if (filesToClean.some(cleanPath => relativePath.endsWith(cleanPath))) {
    // 移除未使用的单独导入
    const patterns = [
      /import\s*{\s*Form\s*}\s*from\s*['"]antd['"]; ?\n?/g,
      /import\s*{\s*Progress\s*}\s*from\s*['"]antd['"]; ?\n?/g,
      /import\s*{\s*List\s*}\s*from\s*['"]antd['"]; ?\n?/g
    ];
    
    patterns.forEach(pattern => {
      if (pattern.test(newContent)) {
        newContent = newContent.replace(pattern, '');
        modified = true;
        console.log(`${filePath}: 移除未使用的单独导入`);
      }
    });
  }
  
  // 清理多余的分号
  newContent = newContent.replace(/;;/g, ';');
  
  return { content: newContent, modified };
}

// 递归处理目录
function processDirectory(dirPath) {
  let totalFixed = 0;
  
  function processDir(currentPath) {
    const items = fs.readdirSync(currentPath);
    
    for (const item of items) {
      const fullPath = path.join(currentPath, item);
      const stat = fs.statSync(fullPath);
      
      if (stat.isDirectory()) {
        // 跳过 node_modules 等目录
        if (!['node_modules', '.git', 'dist', 'build'].includes(item)) {
          processDir(fullPath);
        }
      } else if (item.endsWith('.tsx') || item.endsWith('.ts')) {
        try {
          const content = fs.readFileSync(fullPath, 'utf8');
          const result = fixSpecificImports(content, fullPath);
          
          if (result.modified) {
            fs.writeFileSync(fullPath, result.content, 'utf8');
            totalFixed++;
          }
        } catch (error) {
          console.error(`处理文件 ${fullPath} 时出错:`, error.message);
        }
      }
    }
  }
  
  processDir(dirPath);
  return totalFixed;
}

// 主函数
function main() {
  const srcPath = path.join(__dirname, 'src');
  
  if (!fs.existsSync(srcPath)) {
    console.error('src 目录不存在');
    return;
  }
  
  console.log('开始修复特定的导入问题...');
  const fixedCount = processDirectory(srcPath);
  console.log(`\n修复完成！共处理了 ${fixedCount} 个文件`);
}

main();