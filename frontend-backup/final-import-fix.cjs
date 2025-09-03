const fs = require('fs');
const path = require('path');

// 检查组件是否在代码中被使用
function isComponentUsed(content, componentName) {
  // 检查JSX使用
  const jsxPattern = new RegExp(`<${componentName}[\s>]`, 'g');
  if (jsxPattern.test(content)) return true;
  
  // 检查作为变量使用
  const varPattern = new RegExp(`\b${componentName}\b`, 'g');
  const matches = content.match(varPattern) || [];
  // 如果只在import语句中出现，则认为未使用
  const importMatches = content.match(new RegExp(`import.*${componentName}`, 'g')) || [];
  return matches.length > importMatches.length;
}

// 修复特定文件的导入问题
function fixSpecificImports(filePath, content) {
  let modified = false;
  let newContent = content;
  
  // 检查需要添加的组件
  const componentsToCheck = {
    'Select': /<Select[\s>]|Select\.Option/,
    'Divider': /<Divider[\s>]/,
    'Modal': /Modal\.|<Modal[\s>]/,
    'Form': /<Form[\s>]|Form\./,
    'Input': /<Input[\s>]/,
    'Button': /<Button[\s>]/,
    'Card': /<Card[\s>]/,
    'List': /<List[\s>]|List\./,
    'Table': /<Table[\s>]/,
    'Space': /<Space[\s>]/,
    'Typography': /<Typography[\s>]|Typography\./,
    'message': /message\./
  };
  
  // 查找现有的antd导入行
  const antdImportMatch = newContent.match(/import\s*{([^}]+)}\s*from\s*['"]antd['"];?/);
  
  if (antdImportMatch) {
    const currentImports = antdImportMatch[1]
      .split(',')
      .map(imp => imp.trim())
      .filter(imp => imp.length > 0);
    
    const missingComponents = [];
    
    // 检查每个组件是否需要添加
    for (const [component, pattern] of Object.entries(componentsToCheck)) {
      if (pattern.test(newContent) && !currentImports.includes(component)) {
        missingComponents.push(component);
      }
    }
    
    if (missingComponents.length > 0) {
      const allImports = [...currentImports, ...missingComponents].sort();
      const newImportStatement = `import { ${allImports.join(', ')} } from 'antd';`;
      newContent = newContent.replace(antdImportMatch[0], newImportStatement);
      modified = true;
      console.log(`${filePath}: 添加了 ${missingComponents.join(', ')}`);
    }
  } else {
    // 如果没有antd导入，检查是否需要添加
    const neededComponents = [];
    for (const [component, pattern] of Object.entries(componentsToCheck)) {
      if (pattern.test(newContent)) {
        neededComponents.push(component);
      }
    }
    
    if (neededComponents.length > 0) {
      // 在React导入后添加antd导入
      const reactImportMatch = newContent.match(/import React[^;]*;/);
      if (reactImportMatch) {
        const importStatement = `\nimport { ${neededComponents.sort().join(', ')} } from 'antd';`;
        newContent = newContent.replace(reactImportMatch[0], reactImportMatch[0] + importStatement);
        modified = true;
        console.log(`${filePath}: 新增antd导入 ${neededComponents.join(', ')}`);
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
        // 跳过node_modules等目录
        if (!['node_modules', '.git', 'dist', 'build'].includes(item)) {
          processDir(fullPath);
        }
      } else if (item.endsWith('.tsx') || item.endsWith('.ts')) {
        try {
          const content = fs.readFileSync(fullPath, 'utf8');
          const result = fixSpecificImports(fullPath, content);
          
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
  
  console.log('开始修复导入问题...');
  const processedFiles = processDirectory(srcPath);
  console.log(`\n修复完成！共处理了 ${processedFiles} 个文件`);
}

main();