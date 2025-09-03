const fs = require('fs');
const path = require('path');

// 常见的 Ant Design 组件映射
const ANTD_COMPONENTS = {
  'Avatar': 'antd',
  'Button': 'antd',
  'Card': 'antd',
  'Checkbox': 'antd',
  'Col': 'antd',
  'DatePicker': 'antd',
  'Divider': 'antd',
  'Empty': 'antd',
  'Form': 'antd',
  'Input': 'antd',
  'List': 'antd',
  'Modal': 'antd',
  'Pagination': 'antd',
  'Progress': 'antd',
  'Row': 'antd',
  'Select': 'antd',
  'Slider': 'antd',
  'Space': 'antd',
  'Spin': 'antd',
  'Statistic': 'antd',
  'Switch': 'antd',
  'Table': 'antd',
  'Tabs': 'antd',
  'Tag': 'antd',
  'TimePicker': 'antd',
  'Tooltip': 'antd',
  'Typography': 'antd',
  'Upload': 'antd',
  'message': 'antd'
};

// 常见的 Ant Design 图标映射
const ANTD_ICONS = {
  'EyeOutlined': '@ant-design/icons',
  'EditOutlined': '@ant-design/icons',
  'DeleteOutlined': '@ant-design/icons',
  'PlusOutlined': '@ant-design/icons',
  'SearchOutlined': '@ant-design/icons',
  'UserOutlined': '@ant-design/icons',
  'SettingOutlined': '@ant-design/icons',
  'HeartOutlined': '@ant-design/icons',
  'ShareAltOutlined': '@ant-design/icons',
  'EnvironmentOutlined': '@ant-design/icons',
  'CalendarOutlined': '@ant-design/icons',
  'ClockCircleOutlined': '@ant-design/icons',
  'CheckCircleOutlined': '@ant-design/icons',
  'ExclamationCircleOutlined': '@ant-design/icons',
  'InfoCircleOutlined': '@ant-design/icons',
  'WarningOutlined': '@ant-design/icons',
  'CloseOutlined': '@ant-design/icons',
  'DownloadOutlined': '@ant-design/icons',
  'UploadOutlined': '@ant-design/icons',
  'CopyOutlined': '@ant-design/icons',
  'LinkOutlined': '@ant-design/icons'
};

// 检查组件是否在文件中被使用
function isComponentUsed(content, componentName) {
  // 检查 JSX 使用
  const jsxPattern = new RegExp(`<${componentName}[\\s>]`, 'g');
  if (jsxPattern.test(content)) return true;
  
  // 检查作为属性使用 (如 Input.Password)
  const propPattern = new RegExp(`${componentName}\\.`, 'g');
  if (propPattern.test(content)) return true;
  
  // 检查函数调用 (如 message.success)
  const callPattern = new RegExp(`${componentName}\\(`, 'g');
  if (callPattern.test(content)) return true;
  
  return false;
}

// 检查是否已经导入了某个组件
function hasImport(content, componentName, packageName) {
  const importRegex = new RegExp(`import\\s*{[^}]*\\b${componentName}\\b[^}]*}\\s*from\\s*['"]${packageName}['"]`, 'g');
  return importRegex.test(content);
}

// 添加缺失的导入
function addMissingImports(content, filePath) {
  let modified = false;
  let newContent = content;
  
  // 检查 Ant Design 组件
  const missingAntdComponents = [];
  for (const [component, packageName] of Object.entries(ANTD_COMPONENTS)) {
    if (isComponentUsed(content, component) && !hasImport(content, component, packageName)) {
      missingAntdComponents.push(component);
    }
  }
  
  // 检查 Ant Design 图标
  const missingAntdIcons = [];
  for (const [icon, packageName] of Object.entries(ANTD_ICONS)) {
    if (isComponentUsed(content, icon) && !hasImport(content, icon, packageName)) {
      missingAntdIcons.push(icon);
    }
  }
  
  // 添加 antd 组件导入
  if (missingAntdComponents.length > 0) {
    const existingAntdImportMatch = newContent.match(/import\s*{([^}]*)}\s*from\s*['"]antd['"]/g);
    
    if (existingAntdImportMatch) {
      // 更新现有的 antd 导入
      const existingImport = existingAntdImportMatch[0];
      const existingComponents = existingImport.match(/{([^}]*)}/)[1]
        .split(',')
        .map(c => c.trim())
        .filter(c => c.length > 0);
      
      const allComponents = [...new Set([...existingComponents, ...missingAntdComponents])].sort();
      const newImport = `import { ${allComponents.join(', ')} } from 'antd';`;
      
      newContent = newContent.replace(existingImport, newImport);
      modified = true;
    } else {
      // 添加新的 antd 导入
      const importStatement = `import { ${missingAntdComponents.sort().join(', ')} } from 'antd';\n`;
      newContent = importStatement + newContent;
      modified = true;
    }
  }
  
  // 添加 @ant-design/icons 导入
  if (missingAntdIcons.length > 0) {
    const existingIconsImportMatch = newContent.match(/import\s*{([^}]*)}\s*from\s*['"]@ant-design\/icons['"]/g);
    
    if (existingIconsImportMatch) {
      // 更新现有的图标导入
      const existingImport = existingIconsImportMatch[0];
      const existingIcons = existingImport.match(/{([^}]*)}/)[1]
        .split(',')
        .map(c => c.trim())
        .filter(c => c.length > 0);
      
      const allIcons = [...new Set([...existingIcons, ...missingAntdIcons])].sort();
      const newImport = `import { ${allIcons.join(', ')} } from '@ant-design/icons';`;
      
      newContent = newContent.replace(existingImport, newImport);
      modified = true;
    } else {
      // 添加新的图标导入
      const importStatement = `import { ${missingAntdIcons.sort().join(', ')} } from '@ant-design/icons';\n`;
      // 在 React 导入之后添加
      const reactImportMatch = newContent.match(/import\s+React[^;]*;\n/);
      if (reactImportMatch) {
        newContent = newContent.replace(reactImportMatch[0], reactImportMatch[0] + importStatement);
      } else {
        newContent = importStatement + newContent;
      }
      modified = true;
    }
  }
  
  if (modified) {
    console.log(`修复了 ${filePath} 中的导入问题`);
    if (missingAntdComponents.length > 0) {
      console.log(`  添加的 antd 组件: ${missingAntdComponents.join(', ')}`);
    }
    if (missingAntdIcons.length > 0) {
      console.log(`  添加的图标: ${missingAntdIcons.join(', ')}`);
    }
  }
  
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
          const result = addMissingImports(content, fullPath);
          
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
  
  console.log('开始修复缺失的导入...');
  const fixedCount = processDirectory(srcPath);
  console.log(`\n修复完成！共处理了 ${fixedCount} 个文件`);
}

main();