const fs = require('fs');
const path = require('path');

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
  
  // 检查解构使用 (如 const { Option } = Select)
  const destructurePattern = new RegExp(`{[^}]*\\b${componentName}\\b[^}]*}\\s*=`, 'g');
  if (destructurePattern.test(content)) return true;
  
  return false;
}

// 清理未使用的导入
function cleanupUnusedImports(content, filePath) {
  let modified = false;
  let newContent = content;
  
  // 处理 antd 导入
  const antdImportRegex = /import\s*{([^}]*)}\s*from\s*['"]antd['"]/g;
  const antdMatch = antdImportRegex.exec(newContent);
  
  if (antdMatch) {
    const importedComponents = antdMatch[1]
      .split(',')
      .map(c => c.trim())
      .filter(c => c.length > 0);
    
    const usedComponents = importedComponents.filter(component => 
      isComponentUsed(newContent, component)
    );
    
    if (usedComponents.length !== importedComponents.length) {
      if (usedComponents.length > 0) {
        const newImport = `import { ${usedComponents.join(', ')} } from 'antd';`;
        newContent = newContent.replace(antdMatch[0], newImport);
      } else {
        // 移除整个导入行
        newContent = newContent.replace(antdMatch[0] + ';', '');
        newContent = newContent.replace(antdMatch[0], '');
      }
      modified = true;
      
      const removedComponents = importedComponents.filter(c => !usedComponents.includes(c));
      if (removedComponents.length > 0) {
        console.log(`${filePath}: 移除未使用的 antd 组件: ${removedComponents.join(', ')}`);
      }
    }
  }
  
  // 处理 @ant-design/icons 导入
  const iconsImportRegex = /import\s*{([^}]*)}\s*from\s*['"]@ant-design\/icons['"]/g;
  const iconsMatch = iconsImportRegex.exec(newContent);
  
  if (iconsMatch) {
    const importedIcons = iconsMatch[1]
      .split(',')
      .map(c => c.trim())
      .filter(c => c.length > 0);
    
    const usedIcons = importedIcons.filter(icon => 
      isComponentUsed(newContent, icon)
    );
    
    if (usedIcons.length !== importedIcons.length) {
      if (usedIcons.length > 0) {
        const newImport = `import { ${usedIcons.join(', ')} } from '@ant-design/icons';`;
        newContent = newContent.replace(iconsMatch[0], newImport);
      } else {
        // 移除整个导入行
        newContent = newContent.replace(iconsMatch[0] + ';', '');
        newContent = newContent.replace(iconsMatch[0], '');
      }
      modified = true;
      
      const removedIcons = importedIcons.filter(c => !usedIcons.includes(c));
      if (removedIcons.length > 0) {
        console.log(`${filePath}: 移除未使用的图标: ${removedIcons.join(', ')}`);
      }
    }
  }
  
  // 添加缺失的图标
  const missingIcons = [];
  const iconPatterns = {
    'ThunderboltOutlined': /<ThunderboltOutlined/,
    'DashboardOutlined': /<DashboardOutlined/,
    'ClockCircleOutlined': /<ClockCircleOutlined/,
    'WarningOutlined': /<WarningOutlined/,
    'CheckCircleOutlined': /<CheckCircleOutlined/,
    'ExclamationCircleOutlined': /<ExclamationCircleOutlined/,
    'ReloadOutlined': /<ReloadOutlined/,
    'BugOutlined': /<BugOutlined/,
    'RocketOutlined': /<RocketOutlined/,
    'MonitorOutlined': /<MonitorOutlined/
  };
  
  for (const [icon, pattern] of Object.entries(iconPatterns)) {
    if (pattern.test(newContent) && !newContent.includes(`import { ${icon}`)) {
      missingIcons.push(icon);
    }
  }
  
  if (missingIcons.length > 0) {
    // 检查是否已有 @ant-design/icons 导入
    const existingIconsMatch = newContent.match(/import\s*{([^}]*)}\s*from\s*['"]@ant-design\/icons['"]/g);
    
    if (existingIconsMatch) {
      // 更新现有导入
      const existingImport = existingIconsMatch[0];
      const existingIcons = existingImport.match(/{([^}]*)}/)[1]
        .split(',')
        .map(c => c.trim())
        .filter(c => c.length > 0);
      
      const allIcons = [...new Set([...existingIcons, ...missingIcons])].sort();
      const newImport = `import { ${allIcons.join(', ')} } from '@ant-design/icons';`;
      
      newContent = newContent.replace(existingImport, newImport);
    } else {
      // 添加新的导入
      const importStatement = `import { ${missingIcons.sort().join(', ')} } from '@ant-design/icons';\n`;
      const reactImportMatch = newContent.match(/import\s+React[^;]*;\n/);
      if (reactImportMatch) {
        newContent = newContent.replace(reactImportMatch[0], reactImportMatch[0] + importStatement);
      } else {
        newContent = importStatement + newContent;
      }
    }
    
    modified = true;
    console.log(`${filePath}: 添加缺失的图标: ${missingIcons.join(', ')}`);
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
          const result = cleanupUnusedImports(content, fullPath);
          
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
  
  console.log('开始清理未使用的导入并添加缺失的图标...');
  const fixedCount = processDirectory(srcPath);
  console.log(`\n清理完成！共处理了 ${fixedCount} 个文件`);
}

main();