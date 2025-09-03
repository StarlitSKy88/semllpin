const fs = require('fs');
const path = require('path');

// 获取所有TypeScript文件
function getAllTsFiles(dir) {
  const files = [];
  const items = fs.readdirSync(dir);
  
  for (const item of items) {
    const fullPath = path.join(dir, item);
    const stat = fs.statSync(fullPath);
    
    if (stat.isDirectory() && !item.startsWith('.') && item !== 'node_modules') {
      files.push(...getAllTsFiles(fullPath));
    } else if (item.endsWith('.tsx') || item.endsWith('.ts')) {
      files.push(fullPath);
    }
  }
  
  return files;
}

// 修复文件中的未使用导入
function fixUnusedImports(filePath) {
  let content = fs.readFileSync(filePath, 'utf8');
  let modified = false;
  
  // 常见的未使用导入模式
  const unusedPatterns = [
    // Ant Design 组件
    /,\s*Tooltip(?=\s*[,}])/g,
    /,\s*Divider(?=\s*[,}])/g,
    /,\s*Button(?=\s*[,}])/g,
    /,\s*Modal(?=\s*[,}])/g,
    /,\s*Select(?=\s*[,}])/g,
    /,\s*Input(?=\s*[,}])/g,
    /,\s*DatePicker(?=\s*[,}])/g,
    /,\s*Switch(?=\s*[,}])/g,
    /,\s*Badge(?=\s*[,}])/g,
    /,\s*List(?=\s*[,}])/g,
    /,\s*Timeline(?=\s*[,}])/g,
    /,\s*Alert(?=\s*[,}])/g,
    
    // Ant Design 图标
    /,\s*SettingOutlined(?=\s*[,}])/g,
    /,\s*EyeOutlined(?=\s*[,}])/g,
    /,\s*BugOutlined(?=\s*[,}])/g,
    /,\s*LoadingOutlined(?=\s*[,}])/g,
    /,\s*CheckCircleOutlined(?=\s*[,}])/g,
    /,\s*InfoCircleOutlined(?=\s*[,}])/g,
    /,\s*WarningOutlined(?=\s*[,}])/g,
    /,\s*ThunderboltOutlined(?=\s*[,}])/g,
    
    // Recharts 组件
    /,\s*BarChart(?=\s*[,}])/g,
    /,\s*Bar(?=\s*[,}])/g,
  ];
  
  // 应用修复模式
  for (const pattern of unusedPatterns) {
    const newContent = content.replace(pattern, '');
    if (newContent !== content) {
      content = newContent;
      modified = true;
    }
  }
  
  // 清理空的导入行
  content = content.replace(/import\s*{\s*}\s*from\s*['"][^'"]*['"];?\n?/g, '');
  
  // 清理多余的逗号
  content = content.replace(/,\s*}/g, ' }');
  content = content.replace(/{\s*,/g, '{ ');
  
  if (modified) {
    fs.writeFileSync(filePath, content, 'utf8');
    console.log(`Fixed: ${filePath}`);
  }
  
  return modified;
}

// 主函数
function main() {
  const srcDir = path.join(__dirname, 'src');
  const files = getAllTsFiles(srcDir);
  
  let totalFixed = 0;
  
  for (const file of files) {
    if (fixUnusedImports(file)) {
      totalFixed++;
    }
  }
  
  console.log(`\nFixed ${totalFixed} files with unused imports.`);
}

if (require.main === module) {
  main();
}