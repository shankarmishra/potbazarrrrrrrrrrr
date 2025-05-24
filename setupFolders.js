import fs from 'fs';
import path from 'path';

const folders = [
  'public/uploads/category_images',
  'public/uploads/subcategory_images',
  'public/uploads/product_images'
];

folders.forEach(folder => {
  const dir = path.join(process.cwd(), folder);
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
    console.log(`Created folder: ${dir}`);
  } else {
    console.log(`Folder already exists: ${dir}`);
  }
});
