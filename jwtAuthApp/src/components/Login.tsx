import { useDispatch, useSelector } from "react-redux";
import { useNavigate } from "react-router-dom";
import { RootState } from "../redux/store/store";
import { setUserField, loginFetch } from "../redux/state/userState";

const Login = () => {
    const dispatch = useDispatch();
    const navigate = useNavigate();
    const userInput = useSelector((state: RootState) => state.InputReducer);
    const { username, password } = userInput;
    const isAuthenticated = useSelector((state: RootState) => state.UserReducer.isAuthenticated);

    const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
        const { name, value } = e.target;
        dispatch(setUserField({ [ name ]: value }));
    };

    const onSubmitForm = (e: React.FormEvent<HTMLFormElement>) => {
        e.preventDefault();
        dispatch(loginFetch({ username, password }));
    };

    if (isAuthenticated) {
        navigate(`/home`);
    }

    return (
        <>
            <form onSubmit={onSubmitForm}>
                <input type="text" name="username" value={username} onChange={handleChange} />
                <input type="password" name="password" value={password} onChange={handleChange} />
                <button type="submit">Login</button>
            </form>
        </>
    );
};

export default Login;
