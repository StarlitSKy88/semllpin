const fs = require('fs');
const path = require('path');

// 所有可能需要的antd组件
const ANTD_COMPONENTS = [
  'Typography', 'Row', 'Col', 'Statistic', 'Alert', 'Tabs', 'Space', 'List', 'Empty', 'Spin', 'Card',
  'Button', 'Input', 'Form', 'Select', 'Divider', 'Modal', 'Table', 'Result', 'message', 'notification',
  'Dropdown', 'Menu', 'Avatar', 'Badge', 'Tag', 'Tooltip', 'Popover', 'Progress', 'Switch', 'Checkbox',
  'Radio', 'DatePicker', 'TimePicker', 'Upload', 'Rate', 'Slider', 'InputNumber', 'AutoComplete',
  'Cascader', 'TreeSelect', 'Transfer', 'Steps', 'Breadcrumb', 'Pagination', 'Anchor', 'BackTop',
  'Affix', 'Drawer', 'Popconfirm', 'Calendar', 'Tree', 'Timeline', 'Collapse', 'Carousel',
  'Comment', 'Descriptions', 'Image', 'Skeleton', 'ConfigProvider'
];

// 检查组件是否在文件中被使用
function isComponentUsed(content, componentName) {
  // 检查JSX标签使用
  const jsxPattern = new RegExp(`<${componentName}[\\s>]`, 'g');
  const closingTagPattern = new RegExp(`</${componentName}>`, 'g');
  
  // 检查对象解构使用（如 Typography.Title）
  const objectPattern = new RegExp(`${componentName}\\.`, 'g');
  
  // 检查直接调用（如 message.success）
  const callPattern = new RegExp(`${componentName}\\.(success|error|info|warning|loading|destroy|config)`, 'g');
  
  return jsxPattern.test(content) || closingTagPattern.test(content) || 
         objectPattern.test(content) || callPattern.test(content);
}

// 修复文件的导入
function fixFileImports(filePath) {
  try {
    const content = fs.readFileSync(filePath, 'utf8');
    
    // 检查是否已有antd导入
    const antdImportMatch = content.match(/import\s*\{([^}]*)\}\s*from\s*['"]antd['"]/s);
    
    if (!antdImportMatch) {
      // 如果没有antd导入，检查是否需要添加
      const usedComponents = ANTD_COMPONENTS.filter(comp => isComponentUsed(content, comp));
      
      if (usedComponents.length > 0) {
        const importStatement = `import { ${usedComponents.join(', ')} } from 'antd';\n`;
        const newContent = importStatement + content;
        fs.writeFileSync(filePath, newContent, 'utf8');
        console.log(`Added antd import to ${filePath}: ${usedComponents.join(', ')}`);
        return true;
      }
    } else {
      // 如果已有antd导入，检查是否需要添加缺失的组件
      const currentImports = antdImportMatch[1]
        .split(',')
        .map(imp => imp.trim())
        .filter(imp => imp.length > 0);
      
      const usedComponents = ANTD_COMPONENTS.filter(comp => isComponentUsed(content, comp));
      const missingComponents = usedComponents.filter(comp => !currentImports.includes(comp));
      
      if (missingComponents.length > 0) {
        const allComponents = [...currentImports, ...missingComponents].sort();
        const newImportStatement = `import { ${allComponents.join(', ')} } from 'antd'`;
        const newContent = content.replace(
          /import\s*\{[^}]*\}\s*from\s*['"]antd['"]/s,
          newImportStatement
        );
        fs.writeFileSync(filePath, newContent, 'utf8');
        console.log(`Updated antd import in ${filePath}: added ${missingComponents.join(', ')}`);
        return true;
      }
    }
    
    return false;
  } catch (error) {
    console.error(`Error processing ${filePath}:`, error.message);
    return false;
  }
}

// 递归处理目录
function processDirectory(dirPath) {
  let processedCount = 0;
  
  function processDir(currentPath) {
    const items = fs.readdirSync(currentPath);
    
    for (const item of items) {
      const fullPath = path.join(currentPath, item);
      const stat = fs.statSync(fullPath);
      
      if (stat.isDirectory() && !item.startsWith('.') && item !== 'node_modules') {
        processDir(fullPath);
      } else if (stat.isFile() && (item.endsWith('.tsx') || item.endsWith('.ts'))) {
        if (fixFileImports(fullPath)) {
          processedCount++;
        }
      }
    }
  }
  
  processDir(dirPath);
  return processedCount;
}

// 主执行函数
function main() {
  const srcPath = path.join(__dirname, 'frontend', 'src');
  
  if (!fs.existsSync(srcPath)) {
    console.error('src directory not found');
    return;
  }
  
  console.log('Starting comprehensive import fix...');
  const processedCount = processDirectory(srcPath);
  console.log(`Comprehensive import fix completed. Processed ${processedCount} files.`);
}

main();