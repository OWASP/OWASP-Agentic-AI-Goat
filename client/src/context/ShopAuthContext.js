import React, { createContext, useContext, useState, useEffect } from 'react';
import axios from 'axios';

const ShopAuthContext = createContext();

export const useShopAuth = () => {
  const context = useContext(ShopAuthContext);
  if (!context) {
    throw new Error('useShopAuth must be used within a ShopAuthProvider');
  }
  return context;
};

export const ShopAuthProvider = ({ children }) => {
  const [shopUser, setShopUser] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    checkAuthStatus();
  }, []);

  const checkAuthStatus = async () => {
    try {
      const token = localStorage.getItem('shop_token');
      const userData = localStorage.getItem('shop_user');
      
      if (token && userData) {
        const parsedUser = JSON.parse(userData);
        setShopUser(parsedUser);
      }
    } catch (error) {
      console.error('Error checking auth status:', error);
      localStorage.removeItem('shop_token');
      localStorage.removeItem('shop_user');
    } finally {
      setLoading(false);
    }
  };

  const login = async (username, password) => {
    try {
      const response = await axios.post('/api/secureshop/auth/login', {
        username,
        password
      });

      if (response.data.success) {
        const { token, user: userData } = response.data;
        localStorage.setItem('shop_token', token);
        localStorage.setItem('shop_user', JSON.stringify(userData));
        setShopUser(userData);
        return { success: true };
      }
    } catch (error) {
      return { 
        success: false, 
        error: error.response?.data?.error || 'Login failed' 
      };
    }
  };

  const register = async (userData) => {
    try {
      const response = await axios.post('/api/secureshop/auth/register', userData);

      if (response.data.success) {
        return { success: true };
      }
    } catch (error) {
      return { 
        success: false, 
        error: error.response?.data?.error || 'Registration failed' 
      };
    }
  };

  const logout = async () => {
    try {
      localStorage.removeItem('shop_token');
      localStorage.removeItem('shop_user');
      setShopUser(null);
      return { success: true };
    } catch (error) {
      console.error('Logout error:', error);
      return { success: false, error: 'Logout failed' };
    }
  };

  const updateShopUser = (userData) => {
    setShopUser(userData);
    localStorage.setItem('shop_user', JSON.stringify(userData));
  };

  const value = {
    shopUser,
    loading,
    shopLogin: login,
    shopRegister: register,
    shopLogout: logout,
    updateShopUser,
    checkAuthStatus
  };

  return (
    <ShopAuthContext.Provider value={value}>
      {children}
    </ShopAuthContext.Provider>
  );
};
