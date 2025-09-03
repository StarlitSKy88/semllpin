const fs = require('fs');
const path = require('path');

// 检查文件中是否使用了特定组件
function isComponentUsed(content, componentName) {
  // 检查JSX使用
  const jsxPattern = new RegExp(`<${componentName}[\s>]`, 'g');
  if (jsxPattern.test(content)) return true;
  
  // 检查解构使用 (如 const { Search } = Input)
  const destructurePattern = new RegExp(`const\s*{[^}]*\b${componentName}\b[^}]*}\s*=`, 'g');
  if (destructurePattern.test(content)) return true;
  
  // 检查属性访问 (如 List.Item)
  const propertyPattern = new RegExp(`\b${componentName}\.[A-Z]`, 'g');
  if (propertyPattern.test(content)) return true;
  
  return false;
}

// 检查是否已经导入了组件
function hasImport(content, componentName, fromModule) {
  const importPattern = new RegExp(`import\s*{[^}]*\b${componentName}\b[^}]*}\s*from\s*['"]${fromModule}['"]`, 'g');
  return importPattern.test(content);
}

// 添加缺失的导入
function addMissingImport(content, componentName, fromModule) {
  // 查找现有的从同一模块的导入
  const existingImportPattern = new RegExp(`(import\s*{)([^}]*)(}\s*from\s*['"]${fromModule}['"])`, 'g');
  const match = existingImportPattern.exec(content);
  
  if (match) {
    // 如果已有从该模块的导入，添加到现有导入中
    const imports = match[2].split(',').map(s => s.trim()).filter(s => s);
    if (!imports.includes(componentName)) {
      imports.push(componentName);
      const newImportLine = `${match[1]} ${imports.join(', ')} ${match[3]}`;
      return content.replace(match[0], newImportLine);
    }
  } else {
    // 如果没有从该模块的导入，创建新的导入行
    const importLine = `import { ${componentName} } from '${fromModule}';\n`;
    // 在第一个import语句之前插入
    const firstImportMatch = content.match(/^import\s+/m);
    if (firstImportMatch) {
      const insertIndex = content.indexOf(firstImportMatch[0]);
      return content.slice(0, insertIndex) + importLine + content.slice(insertIndex);
    } else {
      // 如果没有import语句，在文件开头添加
      return importLine + content;
    }
  }
  
  return content;
}

// 恢复文件中缺失的导入
function restoreImports(filePath) {
  let content = fs.readFileSync(filePath, 'utf8');
  let modified = false;
  
  // 需要检查的组件和它们的模块
  const componentsToCheck = [
    { name: 'Button', module: 'antd' },
    { name: 'Input', module: 'antd' },
    { name: 'List', module: 'antd' },
    { name: 'Select', module: 'antd' },
    { name: 'Modal', module: 'antd' },
    { name: 'Badge', module: 'antd' },
    { name: 'Alert', module: 'antd' },
    { name: 'Card', module: 'antd' },
    { name: 'Form', module: 'antd' },
    { name: 'Table', module: 'antd' },
    { name: 'Tabs', module: 'antd' },
    { name: 'Space', module: 'antd' },
    { name: 'Row', module: 'antd' },
    { name: 'Col', module: 'antd' },
    { name: 'Typography', module: 'antd' },
    { name: 'Spin', module: 'antd' },
    { name: 'Empty', module: 'antd' },
    { name: 'Pagination', module: 'antd' },
    { name: 'Checkbox', module: 'antd' },
    { name: 'Radio', module: 'antd' },
    { name: 'Upload', module: 'antd' },
    { name: 'Progress', module: 'antd' },
    { name: 'Statistic', module: 'antd' },
    { name: 'Tag', module: 'antd' },
    { name: 'Avatar', module: 'antd' },
    { name: 'Image', module: 'antd' },
    { name: 'Drawer', module: 'antd' },
    { name: 'Popover', module: 'antd' },
    { name: 'Dropdown', module: 'antd' },
    { name: 'Menu', module: 'antd' },
    { name: 'Steps', module: 'antd' },
    { name: 'Result', module: 'antd' },
    { name: 'Skeleton', module: 'antd' },
    { name: 'BackTop', module: 'antd' },
    { name: 'Affix', module: 'antd' },
    { name: 'Anchor', module: 'antd' },
    { name: 'Breadcrumb', module: 'antd' },
    { name: 'ConfigProvider', module: 'antd' },
    { name: 'Layout', module: 'antd' },
    { name: 'Grid', module: 'antd' },
    { name: 'Flex', module: 'antd' },
  ];
  
  for (const { name, module } of componentsToCheck) {
    if (isComponentUsed(content, name) && !hasImport(content, name, module)) {
      const newContent = addMissingImport(content, name, module);
      if (newContent !== content) {
        content = newContent;
        modified = true;
      }
    }
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
      if (restoreImports(fullPath)) {
        console.log(`Restored: ${fullPath}`);
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
  
  console.log('Restoring missing imports...');
  const fixedCount = processDirectory(srcDir);
  console.log(`\nRestored imports in ${fixedCount} files.`);
}

if (require.main === module) {
  main();
}