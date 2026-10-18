import React, { createContext, useContext } from 'react';

export const GuestCartChannelContext = createContext(null);
export const useGuestCartChannel = () => useContext(GuestCartChannelContext);
