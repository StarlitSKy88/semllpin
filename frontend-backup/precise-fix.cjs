const fs = require('fs');
const path = require('path');

// 检查组件是否在代码中被使用
function isComponentUsed(content, componentName) {
  // 检查JSX使用
  const jsxPattern = new RegExp(`<${componentName}[\s>]`, 'g');
  if (jsxPattern.test(content)) return true;
  
  // 检查作为变量使用（如 Modal.confirm）
  const varPattern = new RegExp(`\b${componentName}\.`, 'g');
  if (varPattern.test(content)) return true;
  
  // 检查解构使用（如 const { confirm } = Modal）
  const destructurePattern = new RegExp(`{[^}]*}\s*=\s*${componentName}`, 'g');
  if (destructurePattern.test(content)) return true;
  
  return false;
}

// 修复特定文件的导入问题
function fixFileImports(filePath, content) {
  let modified = false;
  let newContent = content;
  
  // 需要检查的antd组件
  const antdComponents = {
    'Statistic': /<Statistic[\s>]/,
    'Modal': /Modal\.|<Modal[\s>]/,
  };
  
  // 需要检查的图标组件
  const iconComponents = {
    'FlagOutlined': /<FlagOutlined[\s>]/,
  };
  
  // 处理antd导入
  const antdImportMatch = newContent.match(/import\s*{([^}]+)}\s*from\s*['"]antd['"];?/);
  
  if (antdImportMatch) {
    const currentImports = antdImportMatch[1]
      .split(',')
      .map(imp => imp.trim())
      .filter(imp => imp.length > 0);
    
    const missingComponents = [];
    const unusedComponents = [];
    
    // 检查缺失的组件
    for (const [component, pattern] of Object.entries(antdComponents)) {
      if (pattern.test(newContent) && !currentImports.includes(component)) {
        missingComponents.push(component);
      }
    }
    
    // 检查未使用的组件
    for (const component of currentImports) {
      if (!isComponentUsed(newContent, component)) {
        unusedComponents.push(component);
      }
    }
    
    if (missingComponents.length > 0 || unusedComponents.length > 0) {
      const finalImports = currentImports
        .filter(imp => !unusedComponents.includes(imp))
        .concat(missingComponents)
        .sort();
      
      const newImportStatement = `import { ${finalImports.join(', ')} } from 'antd';`;
      newContent = newContent.replace(antdImportMatch[0], newImportStatement);
      modified = true;
      
      if (missingComponents.length > 0) {
        console.log(`${filePath}: 添加了 ${missingComponents.join(', ')}`);
      }
      if (unusedComponents.length > 0) {
        console.log(`${filePath}: 移除了 ${unusedComponents.join(', ')}`);
      }
    }
  }
  
  // 处理图标导入
  const iconImportMatch = newContent.match(/import\s*{([^}]+)}\s*from\s*['"]@ant-design\/icons['"];?/);
  
  if (iconImportMatch) {
    const currentIconImports = iconImportMatch[1]
      .split(',')
      .map(imp => imp.trim())
      .filter(imp => imp.length > 0);
    
    const missingIcons = [];
    
    // 检查缺失的图标
    for (const [icon, pattern] of Object.entries(iconComponents)) {
      if (pattern.test(newContent) && !currentIconImports.includes(icon)) {
        missingIcons.push(icon);
      }
    }
    
    if (missingIcons.length > 0) {
      const finalIconImports = [...currentIconImports, ...missingIcons].sort();
      const newIconImportStatement = `import { ${finalIconImports.join(', ')} } from '@ant-design/icons';`;
      newContent = newContent.replace(iconImportMatch[0], newIconImportStatement);
      modified = true;
      console.log(`${filePath}: 添加了图标 ${missingIcons.join(', ')}`);
    }
  } else {
    // 如果没有图标导入，检查是否需要添加
    const neededIcons = [];
    for (const [icon, pattern] of Object.entries(iconComponents)) {
      if (pattern.test(newContent)) {
        neededIcons.push(icon);
      }
    }
    
    if (neededIcons.length > 0) {
      // 在antd导入后添加图标导入
      const antdImportLine = newContent.match(/import\s*{[^}]+}\s*from\s*['"]antd['"];?/);
      if (antdImportLine) {
        const iconImportStatement = `\nimport { ${neededIcons.sort().join(', ')} } from '@ant-design/icons';`;
        newContent = newContent.replace(antdImportLine[0], antdImportLine[0] + iconImportStatement);
        modified = true;
        console.log(`${filePath}: 新增图标导入 ${neededIcons.join(', ')}`);
      }
    }
  }
  
  return { content: newContent, modified };
}

// 递归处理目录
function processDirectory(dirPath) {
  let totalFiles = 0;
  
  function processDir(currentPath) {
    const items = fs.readdirSync(currentPath);
    
    for (const item of items) {
      const fullPath = path.join(currentPath, item);
      const stat = fs.statSync(fullPath);
      
      if (stat.isDirectory()) {
        if (!['node_modules', '.git', 'dist', 'build'].includes(item)) {
          processDir(fullPath);
        }
      } else if (item.endsWith('.tsx') || item.endsWith('.ts')) {
        try {
          const content = fs.readFileSync(fullPath, 'utf8');
          const result = fixFileImports(fullPath, content);
          
          if (result.modified) {
            fs.writeFileSync(fullPath, result.content, 'utf8');
            totalFiles++;
          }
        } catch (error) {
          console.error(`处理文件 ${fullPath} 时出错:`, error.message);
        }
      }
    }
  }
  
  processDir(dirPath);
  return totalFiles;
}

// 主函数
function main() {
  const srcPath = path.join(__dirname, 'src');
  
  if (!fs.existsSync(srcPath)) {
    console.error('src目录不存在');
    return;
  }
  
  console.log('开始精确修复导入问题...');
  const processedFiles = processDirectory(srcPath);
  console.log(`\n修复完成！共处理了 ${processedFiles} 个文件`);
}

main();