export const isValidPassword = (password) => {
    if (typeof password !== "string") return false;

    const trimmed = password.trim();

    const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z]).{8,}$/;
    return passwordRegex.test(trimmed);
};

// Email should follow a proper pattern
export const isValidEmail = (email) => {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return typeof email === "string" && emailRegex.test(email.trim().toLowerCase());
};

// Phone should be digits only and typically 10-15 digits long
export const isValidPhone = (phone) => {
    const phoneRegex = /^\d{10,15}$/;
    return typeof phone === "string" && phoneRegex.test(phone.trim());
};