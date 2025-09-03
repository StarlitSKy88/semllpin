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

// 最终修复导入问题
function finalFixImports(content, filePath) {
  let modified = false;
  let newContent = content;
  
  // 检查是否需要 Alert 组件
  if (/<Alert[\s>]/.test(newContent)) {
    const antdImportRegex = /import\s*{([^}]*)}\s*from\s*['"]antd['"]/;
    const match = newContent.match(antdImportRegex);
    
    if (match && !match[1].includes('Alert')) {
      const components = match[1].split(',').map(c => c.trim()).filter(c => c.length > 0);
      components.push('Alert');
      const newImport = `import { ${components.sort().join(', ')} } from 'antd';`;
      newContent = newContent.replace(match[0], newImport);
      modified = true;
      console.log(`${filePath}: 添加 Alert 导入`);
    }
  }
  
  // 移除未使用的 message 导入
  if (!isComponentUsed(newContent, 'message')) {
    const antdImportRegex = /import\s*{([^}]*)}\s*from\s*['"]antd['"]/;
    const match = newContent.match(antdImportRegex);
    
    if (match && match[1].includes('message')) {
      const components = match[1]
        .split(',')
        .map(c => c.trim())
        .filter(c => c.length > 0 && c !== 'message');
      
      if (components.length > 0) {
        const newImport = `import { ${components.sort().join(', ')} } from 'antd';`;
        newContent = newContent.replace(match[0], newImport);
      } else {
        newContent = newContent.replace(match[0] + ';', '');
        newContent = newContent.replace(match[0], '');
      }
      modified = true;
      console.log(`${filePath}: 移除未使用的 message 导入`);
    }
  }
  
  // 移除未使用的 Modal 导入
  if (!isComponentUsed(newContent, 'Modal')) {
    const antdImportRegex = /import\s*{([^}]*)}\s*from\s*['"]antd['"]/;
    const match = newContent.match(antdImportRegex);
    
    if (match && match[1].includes('Modal')) {
      const components = match[1]
        .split(',')
        .map(c => c.trim())
        .filter(c => c.length > 0 && c !== 'Modal');
      
      if (components.length > 0) {
        const newImport = `import { ${components.sort().join(', ')} } from 'antd';`;
        newContent = newContent.replace(match[0], newImport);
      } else {
        newContent = newContent.replace(match[0] + ';', '');
        newContent = newContent.replace(match[0], '');
      }
      modified = true;
      console.log(`${filePath}: 移除未使用的 Modal 导入`);
    }
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
          const result = finalFixImports(content, fullPath);
          
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
  
  console.log('开始最终修复导入问题...');
  const fixedCount = processDirectory(srcPath);
  console.log(`\n最终修复完成！共处理了 ${fixedCount} 个文件`);
}

main();