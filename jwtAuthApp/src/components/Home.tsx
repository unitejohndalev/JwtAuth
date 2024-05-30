import { useEffect } from "react";
import { useDispatch, useSelector } from "react-redux";
import { useNavigate } from "react-router-dom";
import { getDemoFetch } from "../redux/state/demoState";
import { RootState } from "../redux/store/store";
import { logout } from "../redux/state/userState";

const Home = () => {
    const navigate = useNavigate();
    const dispatch = useDispatch();

    const { demoConsole, error, isLoading } = useSelector((state: RootState) => state.DemoReducer);

    const pageLogout = () => {
        localStorage.removeItem("token");
        localStorage.setItem("isAuthenticated", "false"); 
        dispatch(logout())
        navigate(`/`);

    };

    useEffect(() => {
        dispatch(getDemoFetch());
        
    }, [ dispatch ]);

    const demoState = () => {

        if (error) {
            alert(`Fetch failed: ${error}`);
        } else if (demoConsole) {
            alert("Fetch success");
        }
    }
   
const demoHandle = () => {
    demoState()
    console.log(demoConsole)
}
    return (
        <div>
            Home
            {isLoading ? <p>Loading...</p> : null}
            <button onClick={demoHandle}>Demo Console Backend</button>
            <button onClick={pageLogout}>Logout</button>
        </div>
    );
};

export default Home;
