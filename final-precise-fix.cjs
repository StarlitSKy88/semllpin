const fs = require('fs');
const path = require('path');

// 需要特殊处理的文件和它们缺失的组件
const SPECIFIC_FIXES = {
  'ShareHistoryPage.tsx': ['Typography', 'Input'],
  'SocialPage.tsx': ['Typography', 'Input'],
  'StatsPage.tsx': ['Typography'],
  'TestMapPage.tsx': ['Typography'],
  'PopularSharesPage.tsx': ['Typography'],
  'ProfilePage.tsx': ['Typography'],
  'PerformanceDashboard.tsx': ['Typography'],
  'AdminContentReviewPage.tsx': ['Typography'],
  'AdminSystemConfigPage.tsx': ['Typography'],
  'AdminUserManagementPage.tsx': ['Typography'],
  'LoginPage.tsx': ['Typography']
};

// 需要移除的未使用导入
const REMOVE_UNUSED = {
  'notificationHistoryService.ts': ['notification'],
  'notificationSoundService.ts': ['Rate'],
  'pushNotificationService.ts': ['notification'],
  'socialApi.ts': ['Comment'], // Comment不存在于antd中
  'uiSlice.ts': ['Form'],
  'performance.ts': ['List']
};

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

// 修复特定文件的导入
function fixSpecificFile(filePath, fileName) {
  try {
    const content = fs.readFileSync(filePath, 'utf8');
    let newContent = content;
    let changed = false;
    
    // 添加缺失的组件
    if (SPECIFIC_FIXES[fileName]) {
      const antdImportMatch = content.match(/import\s*\{([^}]*)\}\s*from\s*['"]antd['"]/s);
      
      if (antdImportMatch) {
        const currentImports = antdImportMatch[1]
          .split(',')
          .map(imp => imp.trim())
          .filter(imp => imp.length > 0);
        
        const missingComponents = SPECIFIC_FIXES[fileName].filter(comp => 
          !currentImports.includes(comp) && isComponentUsed(content, comp)
        );
        
        if (missingComponents.length > 0) {
          const allComponents = [...currentImports, ...missingComponents].sort();
          const newImportStatement = `import { ${allComponents.join(', ')} } from 'antd'`;
          newContent = newContent.replace(
            /import\s*\{[^}]*\}\s*from\s*['"]antd['"]/s,
            newImportStatement
          );
          console.log(`Added to ${fileName}: ${missingComponents.join(', ')}`);
          changed = true;
        }
      } else {
        // 如果没有antd导入，添加需要的组件
        const usedComponents = SPECIFIC_FIXES[fileName].filter(comp => isComponentUsed(content, comp));
        if (usedComponents.length > 0) {
          const importStatement = `import { ${usedComponents.join(', ')} } from 'antd';\n`;
          newContent = importStatement + newContent;
          console.log(`Added antd import to ${fileName}: ${usedComponents.join(', ')}`);
          changed = true;
        }
      }
    }
    
    // 移除未使用的导入
    if (REMOVE_UNUSED[fileName]) {
      const antdImportMatch = newContent.match(/import\s*\{([^}]*)\}\s*from\s*['"]antd['"]/s);
      
      if (antdImportMatch) {
        const currentImports = antdImportMatch[1]
          .split(',')
          .map(imp => imp.trim())
          .filter(imp => imp.length > 0);
        
        const toRemove = REMOVE_UNUSED[fileName];
        const filteredImports = currentImports.filter(imp => !toRemove.includes(imp));
        
        if (filteredImports.length !== currentImports.length) {
          if (filteredImports.length === 0) {
            // 移除整个导入语句
            newContent = newContent.replace(/import\s*\{[^}]*\}\s*from\s*['"]antd['"];?\s*\n?/s, '');
          } else {
            const newImportStatement = `import { ${filteredImports.join(', ')} } from 'antd'`;
            newContent = newContent.replace(
              /import\s*\{[^}]*\}\s*from\s*['"]antd['"]/s,
              newImportStatement
            );
          }
          console.log(`Removed from ${fileName}: ${toRemove.join(', ')}`);
          changed = true;
        }
      }
    }
    
    if (changed) {
      fs.writeFileSync(filePath, newContent, 'utf8');
      return true;
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
        if (fixSpecificFile(fullPath, item)) {
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
  
  console.log('Starting final precise import fix...');
  const processedCount = processDirectory(srcPath);
  console.log(`Final precise import fix completed. Processed ${processedCount} files.`);
}

main();