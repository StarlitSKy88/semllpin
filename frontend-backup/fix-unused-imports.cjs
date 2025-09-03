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

// 检查组件是否在文件中被使用
function isComponentUsed(content, componentName) {
  // 检查JSX使用
  const jsxPattern = new RegExp(`<${componentName}[\s>]`, 'g');
  if (jsxPattern.test(content)) return true;
  
  // 检查解构使用
  const destructurePattern = new RegExp(`const\s*{[^}]*${componentName}[^}]*}\s*=`, 'g');
  if (destructurePattern.test(content)) return true;
  
  // 检查直接引用
  const directPattern = new RegExp(`\b${componentName}\b(?!\s*[,}])`, 'g');
  const matches = content.match(directPattern) || [];
  return matches.length > 1; // 大于1表示除了import还有其他使用
}

// 修复文件中的未使用导入
function fixUnusedImports(filePath) {
  let content = fs.readFileSync(filePath, 'utf8');
  let modified = false;
  
  // 只删除确实未使用的导入
  const potentialUnused = [
    'Tooltip', 'Divider', 'Modal', 'DatePicker', 'Switch', 'Timeline',
    'SettingOutlined', 'EyeOutlined', 'LoadingOutlined', 'InfoCircleOutlined', 
    'WarningOutlined', 'ThunderboltOutlined', 'BarChart', 'Bar'
  ];
  
  for (const component of potentialUnused) {
    if (!isComponentUsed(content, component)) {
      const pattern = new RegExp(`,\s*${component}(?=\s*[,}])`, 'g');
      const newContent = content.replace(pattern, '');
      if (newContent !== content) {
        content = newContent;
        modified = true;
      }
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