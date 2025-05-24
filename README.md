<<<<<<< HEAD
# SmartKart Backend

SmartKart Backend is a Node.js and Express-based backend application for an e-commerce platform that sells plants, garden accessories, and seeds. This project includes user authentication, product management, order processing, and an admin panel for managing the store.

## Table of Contents

- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
- [API Endpoints](#api-endpoints)
- [Admin Panel](#admin-panel)
- [Environment Variables](#environment-variables)
- [Contributing](#contributing)
- [License](#license)

## Features

- User authentication (registration, login, and profile management)
- Product management (categories and products)
- Order processing (create orders, view orders)
- Admin panel for managing products, categories, orders, and users
- Razorpay integration for payment processing
- EJS templating for rendering views

## Installation

1. Clone the repository:
    ```sh
    git clone https://github.com/yourusername/smartkart-backend.git
    cd smartkart-backend
    ```

2. Install dependencies:
    ```sh
    npm install
    ```

3. Set up environment variables:
    Create a [.env](http://_vscodecontentref_/1) file in the root directory and add the following variables:
    ```env
    PORT=3000
    MONGO_URI=your_mongodb_uri
    ACCESS_TOKEN_SECRET=your_access_token_secret
    REFRESH_TOKEN_SECRET=your_refresh_token_secret
    COOKIE_PASSWORD=your_cookie_password
    RAZORPAY_KEY_ID=your_razorpay_key_id
    RAZORPAY_PAY_SECRET=your_razorpay_pay_secret
    ADMIN_EMAIL=your_admin_email
    ADMIN_PASSWORD=your_admin_password
    ```

4. Seed the database:
    ```sh
    npm run postinstall
    ```

## Usage

1. Start the server:
    ```sh
    npm start
    ```

2. Open your browser and navigate to `http://localhost:3000` to view the application.

## API Endpoints

### User Routes

- `POST /api/users/register` - Register a new user
- `POST /api/users/login` - Login a user
- `GET /api/users/profile` - Get the logged-in user's profile

### Product Routes

- `POST /api/products/:categoryId` - Get products by category ID

### Order Routes

- `POST /api/orders/transaction` - Create a Razorpay transaction
- `POST /api/orders` - Create an order
- `GET /api/orders/:userId` - Get orders by user ID

### Category Routes

- `GET /api/category` - Get all categories

## Admin Panel

The admin panel is available at `http://localhost:3000/admin`. Use the admin credentials specified in the [.env](http://_vscodecontentref_/2) file to log in.

## Environment Variables

The following environment variables are required for the application to run:

- [PORT](http://_vscodecontentref_/3) - The port on which the server will run
- [MONGO_URI](http://_vscodecontentref_/4) - The MongoDB connection URI
- [ACCESS_TOKEN_SECRET](http://_vscodecontentref_/5) - The secret key for generating access tokens
- [REFRESH_TOKEN_SECRET](http://_vscodecontentref_/6) - The secret key for generating refresh tokens
- [COOKIE_PASSWORD](http://_vscodecontentref_/7) - The password for securing cookies
- [RAZORPAY_KEY_ID](http://_vscodecontentref_/8) - The Razorpay key ID for payment processing
- [RAZORPAY_PAY_SECRET](http://_vscodecontentref_/9) - The Razorpay secret key for payment processing
- [ADMIN_EMAIL](http://_vscodecontentref_/10) - The email address for the admin user
- [ADMIN_PASSWORD](http://_vscodecontentref_/11) - The password for the admin user

## Contributing

Contributions are welcome! Please open an issue or submit a pull request for any improvements or bug fixes.

## License

This project is licensed under the MIT License.# SmartKart Backend

SmartKart Backend is a Node.js and Express-based backend application for an e-commerce platform that sells plants, garden accessories, and seeds. This project includes user authentication, product management, order processing, and an admin panel for managing the store.

## Table of Contents

- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
- [API Endpoints](#api-endpoints)
- [Admin Panel](#admin-panel)
- [Environment Variables](#environment-variables)
- [Contributing](#contributing)
- [License](#license)

## Features

- User authentication (registration, login, and profile management)
- Product management (categories and products)
- Order processing (create orders, view orders)
- Admin panel for managing products, categories, orders, and users
- Razorpay integration for payment processing
- EJS templating for rendering views

## Installation

1. Clone the repository:
    ```sh
    git clone https://github.com/yourusername/smartkart-backend.git
    cd smartkart-backend
    ```

2. Install dependencies:
    ```sh
    npm install
    ```

3. Set up environment variables:
    Create a [.env](http://_vscodecontentref_/1) file in the root directory and add the following variables:
    ```env
    PORT=3000
    MONGO_URI=your_mongodb_uri
    ACCESS_TOKEN_SECRET=your_access_token_secret
    REFRESH_TOKEN_SECRET=your_refresh_token_secret
    COOKIE_PASSWORD=your_cookie_password
    RAZORPAY_KEY_ID=your_razorpay_key_id
    RAZORPAY_PAY_SECRET=your_razorpay_pay_secret
    ADMIN_EMAIL=your_admin_email
    ADMIN_PASSWORD=your_admin_password
    ```

4. Seed the database:
    ```sh
    npm run postinstall
    ```

## Usage

1. Start the server:
    ```sh
    npm start
    ```

2. Open your browser and navigate to `http://localhost:3000` to view the application.

## API Endpoints

### User Routes

- `POST /api/users/register` - Register a new user
- `POST /api/users/login` - Login a user
- `GET /api/users/profile` - Get the logged-in user's profile

### Product Routes

- `POST /api/products/:categoryId` - Get products by category ID

### Order Routes

- `POST /api/orders/transaction` - Create a Razorpay transaction
- `POST /api/orders` - Create an order
- `GET /api/orders/:userId` - Get orders by user ID

### Category Routes

- `GET /api/category` - Get all categories

## Admin Panel

The admin panel is available at `http://localhost:3000/admin`. Use the admin credentials specified in the [.env](http://_vscodecontentref_/2) file to log in.

## Environment Variables

The following environment variables are required for the application to run:

- [PORT](http://_vscodecontentref_/3) - The port on which the server will run
- [MONGO_URI](http://_vscodecontentref_/4) - The MongoDB connection URI
- [ACCESS_TOKEN_SECRET](http://_vscodecontentref_/5) - The secret key for generating access tokens
- [REFRESH_TOKEN_SECRET](http://_vscodecontentref_/6) - The secret key for generating refresh tokens
- [COOKIE_PASSWORD](http://_vscodecontentref_/7) - The password for securing cookies
- [RAZORPAY_KEY_ID](http://_vscodecontentref_/8) - The Razorpay key ID for payment processing
- [RAZORPAY_PAY_SECRET](http://_vscodecontentref_/9) - The Razorpay secret key for payment processing
- [ADMIN_EMAIL](http://_vscodecontentref_/10) - The email address for the admin user
- [ADMIN_PASSWORD](http://_vscodecontentref_/11) - The password for the admin user

## Contributing

Contributions are welcome! Please open an issue or submit a pull request for any improvements or bug fixes.

## License

This project is licensed under the MIT License.
=======
# potbazzar
>>>>>>> 29d4a6e393e1919816e891b44add38fe5dc0b560
