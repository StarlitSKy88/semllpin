const fs = require('fs');
const path = require('path');

// 修复重复导入
function fixDuplicateImports(filePath) {
  let content = fs.readFileSync(filePath, 'utf8');
  let modified = false;
  
  // 查找所有从 antd 的导入
  const antdImportRegex = /import\s*{([^}]+)}\s*from\s*['"]antd['"];?/g;
  const matches = [];
  let match;
  
  while ((match = antdImportRegex.exec(content)) !== null) {
    matches.push({
      fullMatch: match[0],
      imports: match[1].split(',').map(s => s.trim()).filter(s => s),
      index: match.index
    });
  }
  
  if (matches.length > 1) {
    // 合并所有导入
    const allImports = new Set();
    matches.forEach(m => {
      m.imports.forEach(imp => allImports.add(imp));
    });
    
    // 创建新的导入行
    const newImportLine = `import { ${Array.from(allImports).sort().join(', ')} } from 'antd';`;
    
    // 移除所有旧的导入行（从后往前删除以保持索引正确）
    matches.sort((a, b) => b.index - a.index);
    for (const m of matches) {
      content = content.substring(0, m.index) + content.substring(m.index + m.fullMatch.length);
    }
    
    // 在第一个导入位置添加新的合并导入
    const firstImportIndex = matches[matches.length - 1].index;
    content = content.substring(0, firstImportIndex) + newImportLine + '\n' + content.substring(firstImportIndex);
    
    modified = true;
  }
  
  // 查找所有从 @ant-design/icons 的导入
  const iconImportRegex = /import\s*{([^}]+)}\s*from\s*['"]@ant-design\/icons['"];?/g;
  const iconMatches = [];
  
  while ((match = iconImportRegex.exec(content)) !== null) {
    iconMatches.push({
      fullMatch: match[0],
      imports: match[1].split(',').map(s => s.trim()).filter(s => s),
      index: match.index
    });
  }
  
  if (iconMatches.length > 1) {
    // 合并所有图标导入
    const allIconImports = new Set();
    iconMatches.forEach(m => {
      m.imports.forEach(imp => allIconImports.add(imp));
    });
    
    // 创建新的图标导入行
    const newIconImportLine = `import { ${Array.from(allIconImports).sort().join(', ')} } from '@ant-design/icons';`;
    
    // 移除所有旧的图标导入行（从后往前删除以保持索引正确）
    iconMatches.sort((a, b) => b.index - a.index);
    for (const m of iconMatches) {
      content = content.substring(0, m.index) + content.substring(m.index + m.fullMatch.length);
    }
    
    // 在第一个图标导入位置添加新的合并导入
    const firstIconImportIndex = iconMatches[iconMatches.length - 1].index;
    content = content.substring(0, firstIconImportIndex) + newIconImportLine + '\n' + content.substring(firstIconImportIndex);
    
    modified = true;
  }
  
  if (modified) {
    fs.writeFileSync(filePath, content, 'utf8');
    return true;
  }
  
  return false;
}

// 遍历目录
function processDirectory(dirPath) {
  const files = fs.readdirSync(dirPath);
  let fixedCount = 0;
  
  for (const file of files) {
    const fullPath = path.join(dirPath, file);
    const stat = fs.statSync(fullPath);
    
    if (stat.isDirectory() && !file.startsWith('.') && file !== 'node_modules') {
      fixedCount += processDirectory(fullPath);
    } else if (file.endsWith('.tsx') || file.endsWith('.ts')) {
      if (fixDuplicateImports(fullPath)) {
        console.log(`Fixed: ${fullPath}`);
        fixedCount++;
      }
    }
  }
  
  return fixedCount;
}

// 主函数
function main() {
  const srcDir = path.join(__dirname, 'src');
  
  if (!fs.existsSync(srcDir)) {
    console.error('src directory not found');
    return;
  }
  
  console.log('Fixing duplicate imports...');
  const fixedCount = processDirectory(srcDir);
  console.log(`\nFixed duplicate imports in ${fixedCount} files.`);
}

if (require.main === module) {
  main();
}